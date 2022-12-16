// Package summaries defines how taint analysis information can be summarized for a given function.
package summaries

// stdPackages maps the names of standard library packages to the map of summaries for the package.
// This also serves as a reference to use for ignoring packages.
// Each of the maps in stdPackages map the function string (function.String()) to the summary.
var stdPackages = map[string]map[string]Summary{
	"archive/tar":     SummaryArchiveTar,
	"archive/zip":     SummaryArchiveZip,
	"bufio":           SummaryBufIo,
	"builtin":         SummaryBuiltin,
	"bytes":           SummaryBytes,
	"compress/bzip2":  SummaryCompressBzip2,
	"compress/flate":  SummaryCompressFlate,
	"compress/gzip":   SummaryCompressGzip,
	"compress/lzw":    SummaryCompressLzw,
	"compress/zlib":   SummaryCompressZlib,
	"container":       SummaryContainer,
	"container/heap":  SummaryContainer,
	"container/list":  SummaryContainer,
	"context":         SummaryContext,
	"crypto":          SummaryCrypto,
	"crypto/aes":      SummaryCrypto,
	"crypto/cipher":   SummaryCrypto,
	"crypto/internal": SummaryCrypto,
	"crypto/tls":      SummaryCrypto,
	"crypto/x509":     SummaryCrypto,
	"database":        SummaryDatabase,
	"debug":           SummaryDebug,
	"embed":           SummaryEmbed,
	"encoding":        SummaryEncoding,
	"encoding/asn1":   SummaryEncoding,
	"encoding/gob":    SummaryEncoding,
	"encoding/json":   SummaryEncoding,
	"encoding/xml":    SummaryEncoding,
	"errors":          SummaryErrors,
	"expvar":          SummaryExpVar,
	"flag":            SummaryFlag,
	"fmt":             SummaryFmt,
	"go":              SummaryGo,
	"hash":            SummaryHash,
	"html":            SummaryHtml,
	"image":           SummaryImage,
	"image/color":     SummaryImage,
	"index":           SummaryIndex,
	"io":              SummaryIo,
	"io/fs":           SummaryIo,
	"log":             SummaryLog,
	"math":            SummaryMath,
	"math/big":        SummaryMath,
	"math/bits":       SummaryMath,
	"math/cmplx":      SummaryMath,
	"math/rand":       SummaryMath,
	"mime":            SummaryMime,
	"net":             SummaryNet,
	"net/http":        SummaryNet,
	"net/netip":       SummaryNet,
	"net/textproto":   SummaryNet,
	"os":              SummaryOs,
	"os/exec":         SummaryOs,
	"path":            SummaryPath,
	"path/filepath":   SummaryPath,
	"plugin":          SummaryPlugin,
	"reflect":         SummaryReflect,
	"regexp":          SummaryRegexp,
	"regexp/syntax":   SummaryRegexp,
	"runtime":         SummaryRuntime,
	"sort":            SummarySort,
	"strconv":         SummaryStrConv,
	"strings":         SummaryStrings,
	"sync":            SummarySync,
	"sync/atomic":     SummarySync,
	"syscall":         SummarySysccall,
	"syscall/js":      SummarySysccall,
	"testing":         SummaryTesting,
	"text":            SummaryText,
	"time":            SummaryTime,
	"unicode":         SummaryUnicode,
	"unicode/utf8":    SummaryUnicode,
	"unsafe":          SummaryUnsafe,

	// Internal

	"internal":                 SummaryInternal,
	"internal/abi":             SummaryInternal,
	"internal/buildcfg":        SummaryInternal,
	"internal/bytealg":         SummaryInternal,
	"internal/cfg":             SummaryInternal,
	"internal/cpu":             SummaryInternal,
	"internal/diff":            SummaryInternal,
	"internal/fmtsort":         SummaryInternal,
	"internal/fuzz":            SummaryInternal,
	"internal/goarch":          SummaryInternal,
	"internal/godebug":         SummaryInternal,
	"internal/goexperiment":    SummaryInternal,
	"internal/goos":            SummaryInternal,
	"internal/goroot":          SummaryInternal,
	"internal/intern":          SummaryInternal,
	"internal/itoa":            SummaryInternal,
	"internal/lazyregexp":      SummaryInternal,
	"internal/lazytemplate":    SummaryInternal,
	"internal/nettrace":        SummaryInternal,
	"internal/obscuretestdata": SummaryInternal,
	"internal/oserror":         SummaryInternal,
	"internal/poll":            SummaryInternal,
	"internal/race":            SummaryInternal,
	"internal/reflectlite":     SummaryInternal,
	"internal/syscall":         SummaryInternal,
	"internal/syscall/execenv": SummaryInternal,
	"internal/syscall/unix":    SummaryInternal,
	"internal/syscall/windows": SummaryInternal,
	"internal/testlog":         SummaryInternal,
	"internal/unsafeheader":    SummaryInternal,
}

var SummaryArchiveTar = map[string]Summary{}

var SummaryArchiveZip = map[string]Summary{}

var SummaryBufIo = map[string]Summary{}

var SummaryBuiltin = map[string]Summary{}

var SummaryBytes = map[string]Summary{
	// func (b *Buffer) Bytes() []byte
	"(*bytes.Buffer).Bytes": {
		[][]int{{0}},
		[][]int{{0}},
	},
}

var SummaryCompressBzip2 = map[string]Summary{}

var SummaryCompressFlate = map[string]Summary{}

var SummaryCompressGzip = map[string]Summary{}

var SummaryCompressLzw = map[string]Summary{}

var SummaryCompressZlib = map[string]Summary{}

var SummaryContainer = map[string]Summary{}

var SummaryContext = map[string]Summary{}

var SummaryCrypto = map[string]Summary{}

var SummaryDatabase = map[string]Summary{}

var SummaryDebug = map[string]Summary{}

var SummaryEmbed = map[string]Summary{}

var SummaryEncoding = map[string]Summary{
	// func Indent(dst *bytes.Buffer, src []byte, prefix, indent string) error
	"encoding/json.Indent": {
		[][]int{{0}, {0}, {0}, {0}}, // all args taint the first
		[][]int{{}, {0}, {0}, {0}},  // all args except first taint return error
	},
	// func Marshal(v any) ([]byte, error)
	"encoding/json.Marshal": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func Unmarshal(data []byte, v any) error
	"encoding/json.Unmarshal": {
		[][]int{{0, 1}, {}},
		[][]int{{0}, {0}},
	},
}

var SummaryErrors = map[string]Summary{}

var SummaryExpVar = map[string]Summary{}

var SummaryFlag = map[string]Summary{}

var SummaryFmt = map[string]Summary{
	"fmt.init":       NoTaintPropagation,
	"fmt.newPrinter": NoTaintPropagation,
	// func Println(a ...any) (n int, err error) {
	"fmt.Println": NoTaintPropagation,
	// func Errorf(format string, a ...interface{}) error
	"fmt.Errorf": NoTaintPropagation,
	// func Fprintf(w io.Writer, format string, a ...any) (n int, err error)
	"fmt.Fprintf": {
		TaintingArgs: [][]int{
			{0}, // w is tainted -> w stays tainted
			{0}},
		TaintingRets: [][]int{
			{},
		},
	},
	//func Sprintf(format string, a ...any) string
	"fmt.Sprintf": FormatterPropagation,
	// func Printf(format string, a ...any) (n int, err error)
	"fmt.Printf": FormatterPropagation,
}

var SummaryGo = map[string]Summary{}

var SummaryHash = map[string]Summary{}

var SummaryHtml = map[string]Summary{}

var SummaryImage = map[string]Summary{}

var SummaryIndex = map[string]Summary{}

var SummaryIo = map[string]Summary{}

var SummaryLog = map[string]Summary{
	"log.Debugf": {[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
}

var SummaryMath = map[string]Summary{}

var SummaryMime = map[string]Summary{}

var SummaryNet = map[string]Summary{}

var SummaryOs = map[string]Summary{}

var SummaryPath = map[string]Summary{
	// func Join(elem ...string) string
	"path.Join":          SingleVarArgPropagation,
	"path/filepath.Join": SingleVarArgPropagation,
}

var SummaryPlugin = map[string]Summary{}

var SummaryReflect = map[string]Summary{}

var SummaryRegexp = map[string]Summary{
	// matching regexp doesn't taint arguments but either taints return
	"regexp.MatchString": {[][]int{}, [][]int{{0}, {0}}},
	"regexp.MatchReader": {[][]int{}, [][]int{{0}, {0}}},
}

var SummaryRuntime = map[string]Summary{}

var SummarySort = map[string]Summary{}

var SummaryStrConv = map[string]Summary{
	"strconv.Itoa": {[][]int{{}}, [][]int{{0}, {0}}},
}

var SummaryStrings = map[string]Summary{
	// func HasPrefix(s, prefix string) bool {
	"strings.HasPrefix": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func HasSuffix(s, prefix string) bool {
	"strings.HasSuffix": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func Split(s, sep string) []string
	"strings.Split": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	//func TrimSpace(s string) string
	"strings.TrimSpace": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func LastIndex(s string, substr string) int
	"strings.LastIndex": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
}

var SummarySync = map[string]Summary{
	"(*sync.Mutex).Unlock": {
		[][]int{{0}},
		[][]int{{}},
	},
	"(*sync.Mutex).Lock": {
		[][]int{{0}},
		[][]int{{}},
	},
}

var SummarySysccall = map[string]Summary{}

var SummaryTesting = map[string]Summary{}

var SummaryText = map[string]Summary{}

var SummaryTime = map[string]Summary{}

var SummaryUnicode = map[string]Summary{}

var SummaryUnsafe = map[string]Summary{}

var SummaryInternal = map[string]Summary{}
