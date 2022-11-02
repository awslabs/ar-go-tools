// Package summaries defines how taint analysis information can be summarized for a given function.
package summaries

// StdPackages maps the names of standard library packages to the map of summaries for the package.
// This also serves as a reference to use for ignoring packages.
var StdPackages = map[string]map[string]Summary{
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

var SummaryBytes = map[string]Summary{}

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

var SummaryEncoding = map[string]Summary{}

var SummaryErrors = map[string]Summary{}

var SummaryExpVar = map[string]Summary{}

var SummaryFlag = map[string]Summary{}

var SummaryFmt = map[string]Summary{
	// func Errorf(format string, a ...interface{}) error
	"fmt.Errorf": {
		TaintingArgs: [][]int{{0}},
		TaintingRets: [][]int{{0}, {0}},
	},
}

var SummaryGo = map[string]Summary{}

var SummaryHash = map[string]Summary{}

var SummaryHtml = map[string]Summary{}

var SummaryImage = map[string]Summary{}

var SummaryIndex = map[string]Summary{}

var SummaryIo = map[string]Summary{}

var SummaryLog = map[string]Summary{}

var SummaryMath = map[string]Summary{}

var SummaryMime = map[string]Summary{}

var SummaryNet = map[string]Summary{}

var SummaryOs = map[string]Summary{}

var SummaryPath = map[string]Summary{}

var SummaryPlugin = map[string]Summary{}

var SummaryReflect = map[string]Summary{}

var SummaryRegexp = map[string]Summary{}

var SummaryRuntime = map[string]Summary{}

var SummarySort = map[string]Summary{}

var SummaryStrConv = map[string]Summary{}

var SummaryStrings = map[string]Summary{}

var SummarySync = map[string]Summary{}

var SummarySysccall = map[string]Summary{}

var SummaryTesting = map[string]Summary{}

var SummaryText = map[string]Summary{}

var SummaryTime = map[string]Summary{}

var SummaryUnicode = map[string]Summary{}

var SummaryUnsafe = map[string]Summary{}

var SummaryInternal = map[string]Summary{}
