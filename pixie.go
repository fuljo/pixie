package main

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	githttp "github.com/AaronO/go-git-http"
	"github.com/spf13/afero"
)

// btsReplace takes a byte string and converts it to the representation used in CUPS
func btsReplace(check []byte) []byte {
	checkLen := len(check)
	b := make([]byte, 2+checkLen)
	copy(b[2:], check)

	// Prepend bigendian length, it's encoded in two bytes
	binary.BigEndian.PutUint16(b, uint16(checkLen))
	return b
}

var (
	printerTo      = envStringFb("IPP_PRINTER_URL", "localhost:631/printers/Virtual_PDF_Printer")
	webhook        = envStringFb("WEBHOOK_URL", "")
	webhookMethod  = envStringFb("WEBHOOK_METHOD", "GET")
	webhookTimeout = envDurationFb("WEBHOOK_TIMEOUT", time.Millisecond*250)
	mergeWebhook   = envBool("WEBHOOK_MERGE")

	pdfAnnotationMode = envStringFb("PDF_ANNOTATION_MODE", "banner")

	pdfUnit        = envStringFb("PDF_UNIT_SIZE", "mm")
	pdfSize        = envStringFb("PDF_PAGE_SIZE", "A4")
	pdfFontDir     = envString("PDF_FONT_DIR")
	pdfInLandscape = envBool("PDF_LANDSCAPE")
	timeoutPdf     = envDurationFb("PDF_REFRESH_DURATION", time.Minute*5)
	cacheFolder    = envStringFb("IPP_CACHE_DIR", "/tmp/pixie/")

	imgDpi = float64(envIntFb("IMAGE_PPI", 120))

	pdfLeftMargin   = float64(envIntFb("PDF_LEFT_MARGIN", 10))
	pdfTopMargin    = float64(envIntFb("PDF_TOP_MARGIN", 15))
	pdfBottomMargin = float64(envIntFb("PDF_BOTTOM_MARGIN", 6))
	pdfLineHeight   = float64(envIntFb("PDF_LINE_HEIGHT", 8))

	pdfTextWatermarkOptions = envStringFb("PDF_TEXT_WATERMARK_OPTIONS",
		"fontname: Courier, points: 12, scalefactor: 1 abs, pos: tr, aligntext: r, offset: -30 -15, fillcolor: #000000, backgroundcolor: #ffffff, rotation: 0")

	listen = envStringFb("LISTEN_ADDR", ":6632")

	ansibleRepoDir = envStringFb("REPO_DIR", "/tmp/repo")

	memFs afero.Fs
)

func ensureFolder(folder *string) {
	*folder = strings.TrimRight(*folder, "/")

	stat, err := os.Stat(*folder)

	// If err is not nill, attempt creation
	if err != nil {
		// Attempt creation
		if err = os.MkdirAll(*folder, 0755); err != nil {
			panic(fmt.Errorf("'%v' does not exist and can't be created; %w", *folder, err))
		}

		stat, err = os.Stat(*folder)
	}

	if err != nil {
		panic(err)
	}

	if !stat.IsDir() {
		panic(fmt.Errorf("'%v' is not a directory", stat.Name()))
	}
}

func init() {
	ensureFolder(&ansibleRepoDir)
	ensureFolder(&cacheFolder)

	memFs = afero.NewMemMapFs()
}

func main() {
	// Get git handler to serve the repo
	git := githttp.New(ansibleRepoDir, "git")
	http.Handle("/git", git)

	// CUPS only uses a single endpoint, all requests to this handler will be rerouted to there.
	var to = btsReplace([]byte("ipp://" + printerTo))
	http.HandleFunc("/", cupsHandler(to))

	panic(http.ListenAndServe(listen, nil))
}
