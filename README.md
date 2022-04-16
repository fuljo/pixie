# Pixie

Pixie is the project containing providing imaging, contest layout management, and printing proxy services for
programming contests.

## Imaging

TODO

## Contest layout management

TODO

## Printing proxy

Oftentimes in programming contests contestants can print their code. The problem then becomes how to know which prints
are for which contestants. Cups, which is often used for printing services on Linux, supports banner pages. Programs
interact with cups and tell it which banner pages to use. Due to this last behaviour banner pages are actually useless.
Not all programs can properly interact with them, or even provide methods of interaction and simply omit them always. In
order to more reliably solve this issue this printer proxy can be used.

The basic premise is that it proxies all requests to a printer supporting the generic CUPS PDF printing PPD and for
every print, prepend a page containing some key-value pairs. These key-value pairs can be setup using the printing URL
and a webhook.

### Key-value pairs

The data to be printed on the banner page is primarily filled with key-value pairs setup through the printer URI. If a
contestant machine is setup to print to the proxy using the URI `localhost:6632/foo=bar/baz=foobar` the extracted pairs
will be in YAML:

```yaml
foo: bar
baz: foobar
```

These pairs will be sorted by key and printed on the first page.

### Webhook
Since URIs are limited in size, and it is preferable to keep them as short as possible. 
To add more data, or have some value calculated dynamically a webhook can be used to provide extra data.
All key-value pairs provided in the printer URI are encoded as a JSON object and sent as the body in the request.
The webhook should return a json object with all data to be printed. 
The response and the data provided through the URI are optionally merged before being printed on the page.

### Image
TODO

## Configuration

All config is done through environment variables. The following variables are available:

| Variable               | Type       | Default       | Description                                                                                                                                                                        |
|------------------------|------------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `IPP_PRINTER_URL`      | `String`   | ""            | The IPP url of the actual printer. e.g. `localhost:631/printers/Virtual_PDF_Printer`                                                                                               |
| `WEBHOOK_URL`          | `String`   | ""            | The webhook-url to call for each print. Leave empty if webhooks are not used.                                                                                                      |
| `WEBHOOK_METHOD`       | `String`   | "GET"         | The HTTP-verb to use for the webhook.                                                                                                                                              |
| `WEBHOOK_TIMEOUT`      | `Duration` | "250ms"       | The webhook timeout before continuing without the webhook results.                                                                                                                 |
| `WEBHOOK_MERGE`        | `Boolean`  | false         | Whether to merge the webhook results with the key-value pairs in the url                                                                                                           |
| `IPP_CACHE_DIR`        | `String`   | "/tmp/pixie/" | Location of the rendered PDF pages.                                                                                                                                                |
| `LISTEN_ADDR`          | `String`   | ":6632"       | The ip and port pair pixie will listen on.                                                                                                                                         |
| `PDF_ANNOTATION_MODE`          | `String`   | "banner"       | How to annotate the document. `banner`: add banner page.                                                                                                                                         |

### Banner page
| Variable               | Type       | Default       | Description                                                                                                                                                                        |
|------------------------|------------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PDF_UNIT_SIZE`        | `String`   | "mm"          | The unit size used on the PDF, either "mm", "cm" or for freedom-units: "in". Empty value implies "mm".                                                                             |
| `PDF_PAGE_SIZE`        | `String`   | "A4"          | Page size of PDFs to be printed. Does not need to match, but for best results should. Allowed values: "A3", "A4", "A5", "Letter", "Legal", or "Tabloid". Empty value implies "A4". |
| `PDF_FONT_DIR`         | `String`   | ""            | File-path for 'special' fonts. Only normal fonts are currently supported. So can be left empty. Empty value implies "./"                                                           |
| `PDF_LANDSCAPE`        | `Boolean`  | false         | Whether the prepended page should be rendered in landscape. If left default, or set to false, the page is rendered in portrait.                                                    |
| `PDF_REFRESH_DURATION` | `Duration` | "5m"          | How long the rendered PDF page will be cached before a rerender is forced. Caching is done based on the key-value pairs set in the printer url                                     |
| `IMAGE_PPI`            | `Integer`  | 120           | What PPI should be used for printing the image.                                                                                                                                    |
| `PDF_LEFT_MARGIN`      | `Integer`  | 10            | The left-margin for the prepended page.                                                                                                                                            |
| `PDF_TOP_MARGIN`       | `Integer`  | 15            | The top-margin for the prepended page.                                                                                                                                             |
| `PDF_BOTTOM_MARGIN`    | `Integer`  | 6             | The bottom-margin for the prepended page. Note, if too much content is added on the page, only the first page is added.                                                            |
| `PDF_LINE_HEIGHT`      | `Integer`  | 8             | The line height of the printed key-value pairs. Since font-size currently cannot be set it must be set to                                                                          |


### Example

`IPP_PRINTER_URL=localhost:631/printers/Virtual_PDF_Printer go run .`
This will connect to a (cups PDF) printer with the cups server running on localhost and the queue name being "Virtual_PDF_Printer".
Then setup a printer using the generic PDF ppd and connect it to `ipp://localhost:6631/aaa=bbb/ccc=ddd`.
When printing to this printer every print should be prepended with an extra page containing two lines:
```
aaa: bbb
ccc: ddd
```