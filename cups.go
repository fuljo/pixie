package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mbenkmann/golib/util"

	"github.com/OpenPrinting/goipp"
	"github.com/jung-kurt/gofpdf"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
)

type (
	readSeekWriter interface {
		io.ReadSeeker
		io.Writer
		io.Closer
	}
)

// cupsHandler is the handler which proxies all cups requests and fixes
func cupsHandler(to []byte) func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		requestedUrl := fmt.Sprintf("ipp://%s/%s", strings.TrimRight(request.Host, "/"), strings.Trim(request.URL.Path, "/"))
		log.Printf("-----------------------------------------------------------\n")
		log.Printf("Request: %s\n", requestedUrl)

		respBts, err := io.ReadAll(request.Body)
		if err != nil {
			panic(err)
		}

		// Read the message
		reader := bytes.NewBuffer(respBts)
		var req goipp.Message
		if err := req.Decode(reader); err != nil {
			panic(err)
		}
		reqBody, err := io.ReadAll(reader)
		if err != nil {
			panic(err)
		}

		// Replace the url
		for _, op := range req.Operation {
			if op.Name == "printer-uri" {
				op.Values[0].V = goipp.String("ipp://" + printerTo)
			}
		}
		ippReq, err := req.EncodeBytes()
		if err != nil {
			panic(err)
		}
		newReqBts := append(ippReq, reqBody...)

		// log.Printf("Post length: %d\n", len(bts))
		// log.Printf("Request:\n")
		// req.Print(os.Stdout, true)

		var newReq io.Reader
		newReq = bytes.NewBuffer(newReqBts)

		// In normal cases, simply proxy the request, only when a document is sent some magic is needed.
		log.Printf("Opcode: %v\n", goipp.Op(req.Code))
		if goipp.Op(req.Code) == goipp.OpSendDocument {
			var rw *io.PipeWriter
			newReq, rw = io.Pipe()

			file, err := os.Create("/tmp/original-body.bin")
			if err != nil {
				panic(err)
			}
			_, err = util.WriteAll(file, reqBody)
			if err != nil {
				panic(err)
			}

			// Search for the PDF header.
			pdfStart := bytes.Index(reqBody, []byte("%PDF"))
			if pdfStart < 0 {
				panic("PDF not found!")
			}
			pjlFooterStart := bytes.LastIndex(bytes.TrimRight(reqBody, "\x1b%-12345X"), []byte("\x1b%-12345X"))
			if pjlFooterStart < 0 {
				pjlFooterStart = len(reqBody)
			}

			pjlHeader := reqBody[:pdfStart]
			pdfBody := reqBody[pdfStart:pjlFooterStart]
			pjlFooter := reqBody[pjlFooterStart:]

			file, err = os.Create("/tmp/pjl-header.bin")
			if err != nil {
				panic(err)
			}
			_, err = util.WriteAll(file, pjlHeader)
			if err != nil {
				panic(err)
			}

			file, err = os.Create("/tmp/original-pdf.bin")
			if err != nil {
				panic(err)
			}
			_, err = util.WriteAll(file, pdfBody)
			if err != nil {
				panic(err)
			}

			file, err = os.Create("/tmp/pjl-footer.bin")
			if err != nil {
				panic(err)
			}
			_, err = util.WriteAll(file, pjlFooter)
			if err != nil {
				panic(err)
			}

			go func() {
				// Write the IPP message.
				if _, err := util.WriteAll(rw, ippReq); err != nil {
					panic(err)
				}

				// Write the first PJL commands.
				if _, err := util.WriteAll(rw, pjlHeader); err != nil {
					panic(err)
				}

				// _, err := util.WriteAll(rw, pdfBody)
				// if err != nil {
				// 	panic(err)
				// }

				// file, err := os.Open("/tmp/test.pdf")
				// b, err := io.ReadAll(file)
				// util.WriteAll(rw, b)

				inRead := bytes.NewReader(pdfBody)
				buffer := new(bytes.Buffer)
				if pdfAnnotationMode == "banner" {
					err = addBannerPage(inRead, buffer, request)
				} else if pdfAnnotationMode == "text-watermark" {
					err = addTextWatermark(inRead, buffer, request)
				} else {
					err = fmt.Errorf("unknown annotation mode: %v", pdfAnnotationMode)
				}
				if err != nil {
					panic(err)
				}
				// Write the real PDF.
				if _, err := util.WriteAll(rw, buffer.Bytes()); err != nil {
					panic(err)
				}

				file, err = os.Create("/tmp/new-pdf.pdf")
				if err != nil {
					panic(err)
				}
				if _, err := util.WriteAll(file, buffer.Bytes()); err != nil {
					panic(err)
				}

				// Write the PJL footer.
				// if _, err := util.WriteAll(rw, pjlFooter); err != nil {
				// 	panic(err)
				// }

				_ = rw.Close()
			}()
		}

		hreq, err := http.NewRequest(request.Method, "http://"+printerTo, newReq)
		if err != nil {
			panic(err)
		}
		for k, values := range request.Header {
			for _, value := range values {
				hreq.Header.Add(k, strings.Replace(value, requestedUrl, "ipp://"+printerTo, -1))
			}
		}

		resp, err := http.DefaultClient.Do(hreq)
		_ = hreq.Body.Close()
		if err != nil {
			panic(err)
		}

		respBts, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		_ = resp.Body.Close()

		var res goipp.Message
		err = res.DecodeBytes(respBts)

		respHeader, err := res.EncodeBytes()
		respHeaderBytes := len(respHeader)
		respBody := respBts[respHeaderBytes:]

		for _, op := range res.Operation {
			if op.Name == "printer-uri" {
				op.Values[0].V = goipp.String(requestedUrl)
			}
		}

		// log.Printf("Previous response length: %d\n", len(respBts))
		// log.Printf("Previous header len: %d\n", respHeaderBytes)
		// log.Printf("Previous body len: %d\n", len(respBody))
		respBts, err = res.EncodeBytes()
		respBts = append(respBts, respBody...)
		// log.Printf("New response length: %d\n", len(respBts))
		// log.Printf("Response:\n")
		// res.Print(os.Stdout, false)

		writer.WriteHeader(resp.StatusCode)
		for k, values := range resp.Header {
			for _, value := range values {
				writer.Header().Add(k, strings.Replace(value, "ipp://"+printerTo, requestedUrl, -1))
			}
		}

		if _, err := writer.Write(respBts); err != nil {
			panic(err)
		}
	}
}

func addTextWatermark(inRead io.ReadSeeker, outWrite io.Writer, request *http.Request) error {
	keys, values := requestToMap(request)

	// Prepare the text
	kvs := []string{}
	for _, k := range keys {
		if !strings.HasPrefix(k, "img") {
			kvs = append(kvs, fmt.Sprintf("%v: %v", k, values[k]))
		}
	}
	text := strings.Join(kvs, " - ")

	// Create the watermark
	onTop := true // true: stamp over text, false: watermark below text
	update := false
	watermark, err := pdfcpu.TextWatermark(text, pdfTextWatermarkOptions, onTop, update, 0)

	if err != nil {
		return err
	}

	// Add watermark to all pages
	// page, err := pdfcpu.PageCount(inRead, nil)
	// log.Printf("Pages: %v %v", page, err)
	err = pdfcpu.AddWatermarks(inRead, outWrite, nil, watermark, nil)

	return err
}

func addBannerPage(inRead io.ReadSeeker, outWrite io.Writer, request *http.Request) error {
	hash := sha1.New()
	hash.Write([]byte(request.URL.Path))
	pdfLocation := fmt.Sprintf("%v/%s.pdf", cacheFolder, base32.StdEncoding.EncodeToString(hash.Sum(nil)))

	stat, stErr := os.Stat(pdfLocation)
	var skipBuild = stErr == nil && stat != nil && time.Now().Before(stat.ModTime().Add(timeoutPdf))

	// Test if the page exists and is recent enough
	var bannerPage readSeekWriter
	var err error
	bannerPage, err = os.OpenFile(pdfLocation, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		skipBuild = false
	}

	// If the cached page is not there, create a buffer which can be used to store the file in
	if bannerPage == nil {
		bannerPage, err = memFs.OpenFile(pdfLocation, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			// TODO log
			panic(err)
		}

		defer memFs.Remove(pdfLocation)
	} else {
		bannerPage.Seek(0, 0)
	}

	pdfParts := []io.ReadSeeker{bannerPage, inRead}
	defer bannerPage.Close()
	if !skipBuild {
		order, mp := requestToMap(request)
		if err := renderPage(bannerPage, order, mp); err != nil {
			// TODO log
			pdfParts = pdfParts[1:]
		} else if _, err := bannerPage.Seek(0, 0); err != nil {
			// TODO log
			pdfParts = pdfParts[1:]
		}
	}
	if err := pdfcpu.Merge(pdfParts, outWrite, nil); err != nil {
		panic(err)
	}

	return err
}

// renderPage renders a single pdf, which will be prefixed to the actual page, i.e. a banner page
func renderPage(outWrite io.Writer, keys keyset, values values) error {
	orientation := "P"
	if pdfInLandscape {
		orientation = "L"
	}

	pdf := gofpdf.New(orientation, pdfUnit, pdfSize, pdfFontDir)
	pdf.AddPage()
	pdf.SetFont("Arial", "", 12)

	yTop := pdfTopMargin
	for _, k := range keys {
		if strings.HasPrefix(k, "img") {
			// The value of this contains either a path, or a url. Load the image and add it
			image, err := loadImage(values[k])
			if err != nil {
				// TODO log
				continue
			}
			defer image.Close()
			mime, found := detectImageType(image)
			if !found {
				// TODO log
				continue
			}

			// Attempt to load the image
			iopts := gofpdf.ImageOptions{ReadDpi: true, ImageType: mime}
			opts := pdf.RegisterImageOptionsReader(k, iopts, image)
			opts.SetDpi(imgDpi)
			pdf.ImageOptions(k, pdfLeftMargin, yTop, 0, 0, true, iopts, 0, "")

			yTop += pdfBottomMargin + opts.Height()
		} else {
			pdf.Text(pdfLeftMargin, yTop+pdfLineHeight, fmt.Sprintf("%v: %v", k, values[k]))
			yTop += pdfBottomMargin + pdfLineHeight
		}
	}

	return pdf.Output(outWrite)
}

func detectImageType(f *os.File) (string, bool) {
	f.Seek(0, 0)
	defer f.Seek(0, 0)
	buff := make([]byte, 512)
	if _, err := f.Read(buff); err != nil {
		return "something went wrong", false
	}

	switch typ := http.DetectContentType(buff); typ {
	case "image/jpeg":
		fallthrough
	case "image/png":
		fallthrough
	case "image/gif":
		return strings.ToUpper(typ[6:]), true
	}

	return "unsupported", false
}

// imageLock keeps track of which images are currently being downloaded.
var imageLock sync.Map

func loadImage(loc string) (*os.File, error) {
	var file *os.File
	var err error

	if strings.HasPrefix(loc, "http") {
		hash := sha1.New()
		hash.Write([]byte(loc))
		var localPath string = fmt.Sprintf("%v/%v", cacheFolder, base32.StdEncoding.EncodeToString(hash.Sum(nil)))
		// Check if local image exists

		file, err = os.OpenFile(localPath, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return file, err
		}

		// Check if the file exists
		_, err := os.Stat(localPath)
		fileExists := err != nil

		// Always download the file
		var wg sync.WaitGroup
		wg.Add(1)
		var ge error
		go func() {
			// Decrement wg, and update the map, signaling retrieval has finished
			defer wg.Done()
			defer imageLock.Store(loc, false)

			// Store that we are loading
			act, loaded := imageLock.LoadOrStore(loc, true)
			if b, _ := act.(bool); fileExists && loaded && b {
				// Only exit if:
				//   1. Something is loaded, signalling some other process might have started downloading, and
				//   2. The loaded value is true, and
				//   3. The file actually exists.

				return
			}

			// File needs to be downloaded
			resp, err := http.Get(loc)
			if err != nil {
				ge = err
				return
			}

			defer resp.Body.Close()

			_, err = io.Copy(file, resp.Body)
			if err != nil {
				ge = err
				return
			}

			_, ge = file.Seek(0, io.SeekStart)
		}()

		// If the file does not exist, wait for the waitgroup
		if !fileExists {
			wg.Wait()
		}

		if ge != nil {
			return nil, ge
		}

	} else {

		file, err = os.Open(loc)

		if err != nil {
			return file, err
		}

		var f os.FileInfo
		if f, err = file.Stat(); err != nil && f.IsDir() {
			err = fmt.Errorf("file is a directory")
		}
	}

	return file, err
}

type (
	keyset []string
	values map[string]string
)

// requestToMap builds a values object from a request. It calls the webhook and merges the data in the request with the
// data returned by webhook.
func requestToMap(request *http.Request) (keyset, values) {
	var ms = make(values)
	var order = make(keyset, 0, 10)

	order = append(order, "imglogo")

	segments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	for _, segment := range segments {
		// Split the segment, only add if the actually is something to add
		keyValues := strings.SplitN(segment, "=", 2)
		if len(keyValues) > 1 {
			order = append(order, keyValues[0])
			ms[keyValues[0]] = keyValues[1]
		} else {
			// TODO error
		}
	}

	if webhook != "" {
		// Call the webhook
		var buf = new(bytes.Buffer)
		json.NewEncoder(buf)
		if err := json.NewEncoder(buf).Encode(ms); err != nil {
			// TODO log
			goto skip
		}

		ctx, cancel := context.WithTimeout(request.Context(), webhookTimeout)
		defer cancel()

		// Call the webhook
		req, err := http.NewRequestWithContext(ctx, webhookMethod, webhook, buf)
		if err != nil {
			// TODO log
			goto skip
		}

		_ = req.Body.Close()
		req.Header.Set("content-type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			// TODO log
			goto skip
		}

		defer resp.Body.Close()
		var mm map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&mm); err != nil {
			// TODO log
			goto skip
		}

		if mergeWebhook {
			for k, v := range mm {
				ms[k] = v
			}
		} else {
			ms = mm
		}
	}

skip:
	return order, ms
}
