package worker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	blazehttp "github.com/chaitin/blazehttp/http"

	"github.com/chaitin/blazehttp/testcases"
)

var mu sync.Mutex

type Progress interface {
	Add(n int) error
}

type Worker struct {
	ctx    context.Context
	cancel context.CancelFunc

	concurrence   int // concurrent connections
	fileList      []string
	jobs          chan *Job
	jobResult     chan *Job
	jobResultDone chan struct{}
	result        *Result
	progressBar   Progress

	addr            string // target addr
	isHttps         bool   // is https
	timeout         int    // connection timeout
	blockStatusCode int    // block status code
	reqHost         string // request host of header
	reqPerSession   bool   // request per session
	useEmbedFS      bool
	resultCh        chan *Result
}

type WorkerOption func(*Worker)

func WithTimeout(timeout int) WorkerOption {
	return func(w *Worker) {
		w.timeout = timeout
	}
}

func WithReqHost(reqHost string) WorkerOption {
	return func(w *Worker) {
		w.reqHost = reqHost
	}
}

func WithReqPerSession(reqPerSession bool) WorkerOption {
	return func(w *Worker) {
		w.reqPerSession = reqPerSession
	}
}

func WithUseEmbedFS(useEmbedFS bool) WorkerOption {
	return func(w *Worker) {
		w.useEmbedFS = useEmbedFS
	}
}

func WithConcurrence(c int) WorkerOption {
	return func(w *Worker) {
		w.concurrence = c
	}
}

func WithResultCh(ch chan *Result) WorkerOption {
	return func(w *Worker) {
		w.resultCh = ch
	}
}

func WithProgressBar(pb Progress) WorkerOption {
	return func(w *Worker) {
		w.progressBar = pb
	}
}

func (w *Worker) Stop() {
	w.cancel()
}

func NewWorker(
	addr string,
	isHttps bool,
	fileList []string,
	blockStatusCode int,
	options ...WorkerOption,
) *Worker {
	w := &Worker{
		concurrence: 10, // default 10

		// payloads
		fileList: fileList,

		// connect target & config
		addr:            addr,
		isHttps:         isHttps,
		timeout:         1000, // 1000ms
		blockStatusCode: blockStatusCode,

		jobs:          make(chan *Job),
		jobResult:     make(chan *Job),
		jobResultDone: make(chan struct{}),

		result: &Result{
			Total: int64(len(fileList)),
		},
	}
	w.ctx, w.cancel = context.WithCancel(context.Background())

	for _, opt := range options {
		opt(w)
	}
	return w
}

type Job struct {
	FilePath string
	Result   *JobResult
}

type JobResult struct {
	IsWhite              bool
	IsPass               bool
	Success              bool
	TimeCost             int64
	StatusCode           int
	Err                  string
	BodyLength           int
	WafResponseTxid      string
	WafResponseRuleid    string
	WafResponseMessage   string
	WafResponsePolicy    string
	WafResponseRequestId string
}

type Result struct {
	Total                  int64 // total poc
	Error                  int64
	Success                int64 // success poc
	SuccessTimeCost        int64 // success success cost
	TN                     int64
	FN                     int64
	TP                     int64
	FP                     int64
	Job                    *Job
	TotalBodyLength        int64
	SuccessTotalBodyLength int64
	FailedTotalBodyLength  int64
}

type Output struct {
	Out string
	Err string
}

func (w *Worker) Run() {
	go func() {
		w.jobProducer()
	}()

	go func() {
		w.processJobResult()
		w.jobResultDone <- struct{}{}
	}()

	wg := sync.WaitGroup{}

	for i := 0; i < w.concurrence; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.runWorker()
		}()
	}
	wg.Wait()

	close(w.jobResult)
	<-w.jobResultDone

	fmt.Println(w.generateResult())
}

func (w *Worker) runWorker() {
	for job := range w.jobs {
		func() {
			defer func() {
				w.jobResult <- job
			}()
			filePath := job.FilePath
			req := new(blazehttp.Request)
			if w.useEmbedFS {
				if err := req.ReadFileFromFS(testcases.EmbedTestCasesFS, filePath); err != nil {
					job.Result.Err = fmt.Sprintf("read request file: %s from embed fs error: %s\n", filePath, err)
					return
				}
			} else {
				if err := req.ReadFile(filePath); err != nil {
					job.Result.Err = fmt.Sprintf("read request file: %s error: %s\n", filePath, err)
					return
				}
			}

			if w.reqHost != "" {
				req.SetHost(w.reqHost)
			} else {
				req.SetHost(w.addr)
			}

			if w.reqPerSession {
				// one http request one connection
				req.SetHeader("Connection", "close")
			}

			bodyLength := req.CalculateContentLength() // 这个方法内部直接修改了 header 的 content-length，然后返回了 content-length

			start := time.Now()
			conn, err := blazehttp.Connect(w.addr, w.isHttps, w.timeout)
			if conn == nil {
				job.Result.Err = fmt.Sprintf("connect to %s failed! error: %v\n", w.addr, err)
				//_, _ = fmt.Fprintf(os.Stdout, "connect to %s failed! error: %v\n", w.addr, err)
				return
			}
			nWrite, err := req.WriteTo(*conn)
			if err != nil {
				job.Result.Err = fmt.Sprintf("send request poc: %s length: %d error: %s", filePath, nWrite, err)
				return
			}

			rsp := new(blazehttp.Response)
			if err = rsp.ReadConn(*conn); err != nil {
				job.Result.Err = fmt.Sprintf("read poc file: %s response, error: %s", filePath, err)
				return
			}

			// 解析 WAF 返回的头部信息
			for _, header := range rsp.Headers {
				key := string(header.Key)
				value := string(header.Value)
				switch key {
				case "Waf-Response-Txid":
					job.Result.WafResponseTxid = value
				case "Waf-Response-Ruleid":
					job.Result.WafResponseRuleid = value
				case "Waf-Response-Message":
					job.Result.WafResponseMessage = value
				case "Waf-Response-Policy":
					job.Result.WafResponsePolicy = value
				case "Waf-Response-RequestId":
					job.Result.WafResponseRequestId = value
				}
			}

			elap := time.Since(start).Nanoseconds()
			(*conn).Close()
			job.Result.Success = true
			if strings.HasSuffix(job.FilePath, "white") {
				job.Result.IsWhite = true // white case
			}

			code := rsp.GetStatusCode()
			job.Result.StatusCode = code
			if code != w.blockStatusCode {
				job.Result.IsPass = true
			}
			job.Result.TimeCost = elap
			job.Result.BodyLength = bodyLength
		}()
	}
}

func (w *Worker) processJobResult() {
	// ********
	file, err := os.OpenFile("job_results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	// Write header
	header := fmt.Sprintf("\n----------\n%s\n", time.Now().Format("2006-01-02 15:04:05"))
	mu.Lock()
	if _, err := file.WriteString(header); err != nil {
		fmt.Printf("Failed to write header to file: %v\n", err)
	}
	mu.Unlock()
	// ********

	for job := range w.jobResult {
		w.result.TotalBodyLength += int64(job.Result.BodyLength)
		if job.Result.Success {
			w.result.Success++
			w.result.SuccessTimeCost += job.Result.TimeCost
			w.result.SuccessTotalBodyLength += int64(job.Result.BodyLength)
			if job.Result.IsWhite {
				if job.Result.IsPass { // 正常放行
					w.result.TN++
				} else { // 误报
					// **********
					//log.Printf("~~~~~err1 file: %v, error: %v", job.FilePath, job.Result.Err)
					//_, _ = fmt.Fprintf(os.Stdout, "~~~~~err1(误报) file: %v, error: %v\n", job.FilePath, job.Result.Err)

					content := fmt.Sprintf("误报\tJob: %s\tRuleId: %s\tSuccess: %v\tError: %s\n", job.FilePath, job.Result.WafResponseRuleid, job.Result.Success, job.Result.Err)
					mu.Lock()
					if _, err := file.WriteString(content); err != nil {
						fmt.Printf("Failed to write to file: %v\n", err)
					}
					mu.Unlock()
					// **********

					w.result.FP++
				}
			} else {
				if job.Result.IsPass { // 漏检
					// **********
					//log.Printf("~~~~~err2 file: %v, error: %v", job.FilePath, job.Result.Err)
					//_, _ = fmt.Fprintf(os.Stdout, "~~~~~err2(漏检) file: %v, error: %v\n", job.FilePath, job.Result.Err)

					content := fmt.Sprintf("漏检\tJob: %s\tRuleId: (null)\tSuccess: %v\tError: %s\n", job.FilePath, job.Result.Success, job.Result.Err)
					mu.Lock()
					if _, err := file.WriteString(content); err != nil {
						fmt.Printf("Failed to write to file: %v\n", err)
					}
					mu.Unlock()
					// **********

					w.result.FN++
				} else { // 正常拦截
					// **********
					content := fmt.Sprintf("正常拦截\tJob: %s\tRuleId: %s\tSuccess: %v\tError: %s\n", job.FilePath, job.Result.WafResponseRuleid, job.Result.Success, job.Result.Err)
					mu.Lock()
					if _, err := file.WriteString(content); err != nil {
						fmt.Printf("Failed to write to file: %v\n", err)
					}
					mu.Unlock()
					// **********

					w.result.TP++
				}
			}
		} else {
			// **********
			//log.Fatalf("~~~~~err file: %v, error: %v", job.FilePath, job.Result.Err)
			//log.Printf("~~~~~err3 file: %v, error: %v", job.FilePath, job.Result.Err)
			_, _ = fmt.Fprintf(os.Stdout, "~~~~~err3(失败) file: %v, error: %v\n", job.FilePath, job.Result.Err)

			content := fmt.Sprintf("失败\tJob: %s\tRuleId: (null)\tSuccess: %v\tError: %s\n", job.FilePath, job.Result.Success, job.Result.Err)
			mu.Lock()
			if _, err := file.WriteString(content); err != nil {
				fmt.Printf("Failed to write to file: %v\n", err)
			}
			mu.Unlock()
			// **********

			w.result.Error++
			w.result.FailedTotalBodyLength += int64(job.Result.BodyLength)
		}
		if w.resultCh != nil {
			r := *w.result
			r.Job = job
			w.resultCh <- &r
		}
	}
}

func (w *Worker) jobProducer() {
	defer close(w.jobs)
	for _, f := range w.fileList {
		select {
		case <-w.ctx.Done():
			return
		default:
			w.jobs <- &Job{
				FilePath: f,
				Result:   &JobResult{},
			}
			if w.progressBar != nil {
				_ = w.progressBar.Add(1)
			}
		}
	}
}

func (w *Worker) generateResult() string {
	// 计算 body length
	// 平均每个请求的 body length
	perReqBodyLengthStr := "NaN"
	if w.result.Total != 0 {
		count := w.result.TotalBodyLength / w.result.Total
		perReqBodyLengthStr = fmt.Sprintf("%d", count)
	}
	// 平均每个成功的请求的 body length
	perReqSuccBodyLengthStr := "NaN"
	if w.result.Success != 0 {
		count := w.result.SuccessTotalBodyLength / w.result.Success
		perReqSuccBodyLengthStr = fmt.Sprintf("%d", count)
	}
	// 平均每个失败的请求的 body length
	perReqFailBodyLengthStr := "NaN"
	if w.result.Error != 0 {
		count := w.result.FailedTotalBodyLength / w.result.Error
		perReqFailBodyLengthStr = fmt.Sprintf("%d", count)
	}

	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("总样本数量: %d    成功: %d    错误: %d\n", w.result.Total, w.result.Success, (w.result.Total - w.result.Success)))
	sb.WriteString(fmt.Sprintf("总样本数量(2): %d    成功: %d    错误: %d\n", w.result.Total, w.result.Success, w.result.Error))
	sb.WriteString(fmt.Sprintf("检出率: %.2f%% (恶意样本总数: %d , 正确拦截: %d , 漏报放行: %d)\n", float64(w.result.TP)*100/float64(w.result.TP+w.result.FN), w.result.TP+w.result.FN, w.result.TP, w.result.FN))
	sb.WriteString(fmt.Sprintf("误报率: %.2f%% (正常样本总数: %d , 正确放行: %d , 误报拦截: %d)\n", float64(w.result.FP)*100/float64(w.result.TN+w.result.FP), w.result.TN+w.result.FP, w.result.TN, w.result.FP))
	sb.WriteString(fmt.Sprintf("准确率: %.2f%% (正确拦截 + 正确放行）/样本总数 \n", float64(w.result.TP+w.result.TN)*100/float64(w.result.TP+w.result.TN+w.result.FP+w.result.FN)))
	sb.WriteString(fmt.Sprintf("平均耗时: %.2f毫秒\n", float64(w.result.SuccessTimeCost)/float64(w.result.Success)/1000000))
	sb.WriteString(fmt.Sprintf("平均耗时: %f/%f/1000000=%f\n", float64(w.result.SuccessTimeCost), float64(w.result.Success), float64(w.result.SuccessTimeCost)/float64(w.result.Success)/1000000))
	sb.WriteString(fmt.Sprintf("平均每个请求的长度(字节): %s\n", perReqBodyLengthStr))
	sb.WriteString(fmt.Sprintf("平均每个成功请求的长度(字节): %s\n", perReqSuccBodyLengthStr))
	sb.WriteString(fmt.Sprintf("平均每个错误请求的长度(字节): %s\n", perReqFailBodyLengthStr))
	return sb.String()
}
