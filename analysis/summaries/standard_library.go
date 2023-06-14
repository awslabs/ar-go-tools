// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package summaries

// stdPackages maps the names of standard library packages to the map of summaries for the package.
// This also serves as a reference to use for ignoring packages.
// Each of the maps in stdPackages map the function string (function.String()) to the summary.
var stdPackages = map[string]map[string]Summary{
	"archive/tar":                 SummaryArchiveTar,
	"archive/zip":                 SummaryArchiveZip,
	"bufio":                       SummaryBufIo,
	"builtin":                     SummaryBuiltin,
	"bytes":                       SummaryBytes,
	"compress/bzip2":              SummaryCompressBzip2,
	"compress/flate":              SummaryCompressFlate,
	"compress/gzip":               SummaryCompressGzip,
	"compress/lzw":                SummaryCompressLzw,
	"compress/zlib":               SummaryCompressZlib,
	"container":                   SummaryContainer,
	"container/heap":              SummaryContainer,
	"container/list":              SummaryContainer,
	"context":                     SummaryContext,
	"crypto":                      SummaryCrypto,
	"crypto/aes":                  SummaryCrypto,
	"crypto/cipher":               SummaryCrypto,
	"crypto/des":                  SummaryCrypto,
	"crypto/ecdsa":                SummaryCrypto,
	"crypto/elliptic":             SummaryCrypto,
	"crypto/internal":             SummaryCrypto,
	"crypto/internal/boring":      SummaryCrypto,
	"crypto/internal/nistec":      SummaryCrypto,
	"crypto/internal/nistec/fiat": SummaryCrypto,
	"crypto/rsa":                  SummaryCrypto,
	"crypto/sha1":                 SummaryCrypto,
	"crypto/tls":                  SummaryCrypto,
	"crypto/x509":                 SummaryCrypto,
	"database":                    SummaryDatabase,
	"debug":                       SummaryDebug,
	"embed":                       SummaryEmbed,
	"encoding":                    SummaryEncoding,
	"encoding/asn1":               SummaryEncoding,
	"encoding/gob":                SummaryEncoding,
	"encoding/binary":             SummaryEncoding,
	"encoding/json":               SummaryEncoding,
	"encoding/xml":                SummaryEncoding,
	"errors":                      SummaryErrors,
	"expvar":                      SummaryExpVar,
	"flag":                        SummaryFlag,
	"fmt":                         SummaryFmt,
	"go":                          SummaryGo,
	"hash":                        SummaryHash,
	"html":                        SummaryHtml,
	"image":                       SummaryImage,
	"image/color":                 SummaryImage,
	"index":                       SummaryIndex,
	"io":                          SummaryIo,
	"io/fs":                       SummaryIo,
	"io/ioutil":                   SummaryIo,
	"log":                         SummaryLog,
	"math":                        SummaryMath,
	"math/big":                    SummaryMath,
	"math/bits":                   SummaryMath,
	"math/cmplx":                  SummaryMath,
	"math/rand":                   SummaryMath,
	"mime":                        SummaryMime,
	"net":                         SummaryNet,
	"net/http":                    SummaryNet,
	"net/netip":                   SummaryNet,
	"net/textproto":               SummaryNet,
	"net/url":                     SummaryNet,
	"os":                          SummaryOs,
	"os/exec":                     SummaryOs,
	"path":                        SummaryPath,
	"path/filepath":               SummaryPath,
	"plugin":                      SummaryPlugin,
	"reflect":                     SummaryReflect,
	"regexp":                      SummaryRegexp,
	"regexp/syntax":               SummaryRegexp,
	"runtime":                     SummaryRuntime,
	"runtime/debug":               SummaryRuntime,
	"sort":                        SummarySort,
	"strconv":                     SummaryStrConv,
	"strings":                     SummaryStrings,
	"sync":                        SummarySync,
	"sync/atomic":                 SummarySync,
	"syscall":                     SummarySyscall,
	"syscall/js":                  SummarySyscall,
	"testing":                     SummaryTesting,
	"text":                        SummaryText,
	"time":                        SummaryTime,
	"unicode":                     SummaryUnicode,
	"unicode/utf8":                SummaryUnicode,
	"unsafe":                      SummaryUnsafe,

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

var SummaryBufIo = map[string]Summary{
	"bufio.NewReader":           SingleVarArgPropagation,
	"bufio.NewReaderSize":       TwoArgPropagation,
	"bufio.NewScanner":          SingleVarArgPropagation,
	"(*bufio.Reader).ReadSlice": TwoArgPropagation,
	"(*bufio.Scanner).Scan": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*bufio.Scanner).Split": TwoArgPropagation,
	"(*bufio.Scanner).Text":  SingleVarArgPropagation,
}

var SummaryBuiltin = map[string]Summary{}

var SummaryBytes = map[string]Summary{
	// func Equal(a, b []byte) bool {
	"bytes.Equal": TwoArgPropagation,
	// func NewBuffer(buf []byte) *Buffer
	"bytes.NewBuffer": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func NewBufferString(s string) *Buffer
	"bytes.NewBufferString": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func NewReader(b []byte) *Reader
	"bytes.NewReader": {
		[][]int{{0}},
		[][]int{{0}},
	},
	"bytes.Runes": SingleVarArgPropagation,
	// func (b *Buffer) Bytes() []byte
	"(*bytes.Buffer).Bytes": {
		[][]int{{0}},
		[][]int{{0}},
	},
	"(*bytes.Buffer).Len": SingleVarArgPropagation,
	// func (b *Buffer) String() string
	"(*bytes.Buffer).String": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (b *Buffer) Write(c) error
	"(*bytes.Buffer).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (b *Buffer) WriteByte(c byte) error
	"(*bytes.Buffer).WriteByte": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (b *Buffer) WriteRune(r rune) (n int, err error)
	"(*bytes.Buffer).WriteRune": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (b *Buffer) WriteString(s string) (n int, err error)
	"(*bytes.Buffer).WriteString": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (b *Buffer) WriteTo(w io.Writer) (n int64, err error)
	"(*bytes.Buffer).WriteTo": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (r *Reader) Seek(offset int64, whence int) (int64, error)
	"(*bytes.Reader).Seek": {
		[][]int{{}, {0}, {0}},
		[][]int{{0}, {0}, {0}},
	},
}

var SummaryCompressBzip2 = map[string]Summary{}

var SummaryCompressFlate = map[string]Summary{}

var SummaryCompressGzip = map[string]Summary{}

var SummaryCompressLzw = map[string]Summary{}

var SummaryCompressZlib = map[string]Summary{}

var SummaryContainer = map[string]Summary{}

var SummaryContext = map[string]Summary{}

var SummaryCrypto = map[string]Summary{
	"crypto/aes.NewCipher":             SingleVarArgPropagation,
	"crypto/cipher.NewGCM":             SingleVarArgPropagation,
	"crypto/tls.X509KeyPair":           TwoArgPropagation,
	"crypto/x509.NewCertPool":          NoDataFlowPropagation,
	"crypto/x509.MarshalPKIXPublicKey": SingleVarArgPropagation,
	"crypto/x509.ParsePKCS1PrivateKey": SingleVarArgPropagation,
	"crypto/x509.SystemCertPool":       NoDataFlowPropagation,
	"(crypto.Hash).New":                SingleVarArgPropagation,
	"(*crypto/tls.Config).Clone":       SingleVarArgPropagation,
	"(*crypto/x509.CertPool).AppendCertsFromPEM": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
}

var SummaryDatabase = map[string]Summary{}

var SummaryDebug = map[string]Summary{}

var SummaryEmbed = map[string]Summary{}

var SummaryEncoding = map[string]Summary{
	"encoding/json.init": NoDataFlowPropagation,
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
	// func MarshalIndent(v any, prefix string, indent string) ([]byte, error)
	"encoding/json.MarshalIndent": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func Unmarshal(data []byte, v any) error
	"encoding/json.Unmarshal": {
		[][]int{{0, 1}, {}},
		[][]int{{0}, {0}},
	},
	// func NewDecoder(r io.Reader) *Decoder
	"encoding/json.NewDecoder": SingleVarArgPropagation,
	"(*encoding/json.Decoder).Decode": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*encoding/json.Decoder).UseNumber": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func NewEncoder(w io.Writer) *Encoder
	"encoding/json.NewEncoder": SingleVarArgPropagation,
	// func (enc *Encoder) Encode(v any) error
	"(*encoding/json.Encoder).Encode": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (enc *Encoder) SetIndent(prefix, indent string)
	"(*encoding/json.Encoder).SetIndent": {
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{}},
	},
	"(encoding/json.Number).Float64": SingleVarArgPropagation,
	"(encoding/json.Number).Int64":   SingleVarArgPropagation,
	"(encoding/json.Number).String":  SingleVarArgPropagation,
	// func NewDecoder(r io.Reader) *Decoder {
	"encoding/xml.NewDecoder": {
		[][]int{{0}},
		[][]int{{0}},
	},
	"(*encoding/xml.Decoder).Decode": TwoArgPropagation,
	// func Unmarshal(data []byte, v any) error
	"encoding/xml.Unmarshal": {
		[][]int{{0, 1}, {}},
		[][]int{{0}, {0}},
	},
}

var SummaryErrors = map[string]Summary{
	"errors.New": SingleVarArgPropagation,
}

var SummaryExpVar = map[string]Summary{}

var SummaryFlag = map[string]Summary{
	//func Arg(i int) string"
	// Does not propagate data flow, unless marked as source
	"flag.Arg": NoDataFlowPropagation,
	//func Args() []string"
	"flag.Args": NoDataFlowPropagation,
	//func Bool(name string, value bool, usage string) *bool
	"flag.Bool": {
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func BoolVar(p *bool, name string, value bool, usage string)
	"flag.BoolVar": {
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func Duration(name string, value time.Duration, usage string) *time.Duration
	"flag.Duration": {
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func DurationVar(p *time.Duration, name string, value time.Duration, usage string)
	"flat.DurationVar": {
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func Float64(name string, value float64, usage string) *float64
	"flag.Float64": {
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Float64Var(p *float64, name string, value float64, usage string)
	"flag.Float64Var": {
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func Int(name string, value int, usage string) *int
	"flag.Int": {
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Int64(name string, value int64, usage string) *int64
	"flag.Int64": {
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Int64Var(p *int64, name string, value int64, usage string)
	"flat.Int64Var": {
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func IntVar(p *int, name string, value int, usage string)
	"flag.IntVar": {
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func NArg() int
	//func NFlag() int
	//func Parse()
	//func Parsed() bool
	//func PrintDefaults()
	//func Set(name, value string) error
	//func String(name string, value string, usage string) *string
	"flag.String": {
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func StringVar(p *string, name string, value string, usage string)
	"flag.StringVar": {
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func TextVar(p encoding.TextUnmarshaler, name string, value encoding.TextMarshaler, ...)
	//func Uint(name string, value uint, usage string) *uint
	"flag.Uint": {
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Uint64(name string, value uint64, usage string) *uint64
	"flag.Uint64": {
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Uint64Var(p *uint64, name string, value uint64, usage string)
	"flag.Uint64Var": {
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func UintVar(p *uint, name string, value uint, usage string)
	"flag.UintVar": {
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func UnquoteUsage(flag *Flag) (name string, usage string)
	//func Var(value Value, name string, usage string)
	//func Visit(fn func(*Flag))
	//func VisitAll(fn func(*Flag))
}

var SummaryFmt = map[string]Summary{
	"fmt.init":       NoDataFlowPropagation,
	"fmt.newPrinter": NoDataFlowPropagation,
	// func Println(a ...any) (n int, err error) {
	"fmt.Println": NoDataFlowPropagation,
	// func Fprintln(w io.Writer, a ...any) (n int, err error)
	"fmt.Fprintln": {
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// func Errorf(format string, a ...interface{}) error
	"fmt.Errorf": NoDataFlowPropagation,
	"fmt.Fprint": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func Fprintf(w io.Writer, format string, a ...any) (n int, err error)
	"fmt.Fprintf": {
		[][]int{
			{0},     // w is tainted -> w stays tainted
			{0, 1},  // format string is tainted -> w is tainted
			{0, 2}}, // some argument tainted -> w is tainted
		[][]int{
			{0}, {0}, {0},
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

var SummaryIo = map[string]Summary{
	// func Copy(dst Writer, src Reader) (written int64, err error)
	"io.Copy": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func CopyBuffer(dst Writer, src Reader, buf []byte) (written int64, err error)
	"io.CopyBuffer": {
		[][]int{{0}, {1, 2}, {0, 2}},
		[][]int{{0}, {0}, {0}},
	},
	// func CopyN(dst Writer, src Reader, n int64) (written int64, err error)
	"io.CopyN": {
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{0}, {0}, {0}},
	},
	// func ReadFull(r Reader, buf []byte) (n int, err error) {
	"io.ReadFull": {
		[][]int{{0, 1}, {0}},
		[][]int{{0}, {0}},
	},
	// func TeeReader(r Reader, w Writer) Reader
	"io.TeeReader": {
		[][]int{{0, 1}, {1}},
		[][]int{{0}, {}},
	},
	"io.MultiWriter": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func(r io.ReaderAt, off int64, n int64) *io.SectionReader
	"io.NewSectionReader": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	"(io/fs.FileMode).IsDir": SingleVarArgPropagation,
	// func ioutil.ReadAll(r io.Reader) ([]byte, error)
	"io/ioutil.ReadAll": {
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func ReadDir(dirname string) ([]fs.FileInfo, error)
	"io/ioutil.ReadDir": {
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func ioutil.ReadFile(filename string) ([]byte, error)
	"io/ioutil.ReadFile": {
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func WriteFile(filename string, data []byte, perm fs.FileMode) error
	"io/ioutil.WriteFile": {
		[][]int{{0}, {0, 1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func NopCloser(r io.Reader) io.ReadCloser
	"io/ioutil.NopCloser": SingleVarArgPropagation,
	// func (*io.PipeWriter).Close() error
	"(*io.PipeWriter).Close": {
		[][]int{{0}},
		[][]int{{0}},
	},
}

var SummaryLog = map[string]Summary{
	"log.Debugf": {[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
	"log.Printf": {[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
	// func (l *Logger) Printf(format string, v ...any)
	"(*log.Logger).Printf": {
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{}, {}, {}},
	},
	// func (l *Logger) Println(v ...any)
	"(*log.Logger).Println": {
		[][]int{{0}, {0, 1}},
		[][]int{{}, {}},
	},
}

var SummaryMath = map[string]Summary{
	"math.init":                    NoDataFlowPropagation,
	"math.Abs":                     SingleVarArgPropagation,
	"math.IsNaN":                   SingleVarArgPropagation,
	"math.IsInf":                   SingleVarArgPropagation,
	"math.Log2":                    SingleVarArgPropagation,
	"math.Max":                     TwoArgPropagation,
	"math.Min":                     TwoArgPropagation,
	"math.Mod":                     TwoArgPropagation,
	"math.Modf":                    SingleVarArgPropagation,
	"math.Pow":                     TwoArgPropagation,
	"math.Pow10":                   SingleVarArgPropagation,
	"math.Round":                   SingleVarArgPropagation,
	"math.RoundToEven":             SingleVarArgPropagation,
	"math/big.init":                NoDataFlowPropagation,
	"math/rand.init":               NoDataFlowPropagation,
	"math/rand.Int":                NoDataFlowPropagation,
	"math/rand.Intn":               NoDataFlowPropagation,
	"math/rand.New":                SingleVarArgPropagation,
	"math/rand.NewSource":          SingleVarArgPropagation,
	"math/rand.Seed":               NoDataFlowPropagation,
	"(*math/big.Float).Set":        TwoArgPropagation,
	"(*math/big.Float).SetFloat64": TwoArgPropagation,
	"(*math/big.Float).SetInf":     TwoArgPropagation,
	"(*math/big.Float).SetInt":     TwoArgPropagation,
	"(*math/big.Float).SetInt64":   TwoArgPropagation,
	// func (r *Rand) Float32() float64
	"(*math/rand.Rand).Float32": NoDataFlowPropagation,
	// func (r *Rand) Float64() float64
	"(*math/rand.Rand).Float64":    NoDataFlowPropagation,
	"(*math/rand.rngSource).Int63": NoDataFlowPropagation,
	"(*math/rand.Rand).Int63n":     NoDataFlowPropagation,
}

var SummaryMime = map[string]Summary{}

var SummaryNet = map[string]Summary{
	// func Dial(network, address string) (Conn, error) {
	"net.Dial": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func SplitHostPort(hostport string) (host, port string, err error)
	"net.SplitHostPort": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func NewRequest(method string, url string, body io.Reader) (*Request, error)
	"net/http.NewRequest": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0, 1}, {0, 1}, {0, 1}},
	},
	"net/http.StatusText": SingleVarArgPropagation,
	// func CanonicalHeaderKey(s string) string
	"net/http.CanonicalHeaderKey": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (c *Client) Do(req *Request) (*Response, error)
	"(*net/http.Client).Do": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (h Header) Add(key string, value string)
	"(net/http.Header).Add": {
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{}, {}, {}},
	},
	// func (h Header) Del(key string)
	"(net/http.Header).Del": {
		[][]int{{0}, {0, 1}},
		[][]int{{}, {}},
	},
	// func (h Header) Get(key string) string
	"(net/http.Header).Get": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (h Header) Set(key string, value string)
	"(net/http.Header).Set": {
		[][]int{{0}, {0}, {0}},
		[][]int{{}, {}, {}},
	},
	// func (r *Request) Context() context.Context
	"(*net/http.Request).Context": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (r *Request) WithContext(ctx context.Context) *Request
	"(*net/http.Request).WithContext": {
		[][]int{{0}, {1}}, // context does not taint receiver
		[][]int{{0}, {1}},
	},
}

var SummaryOs = map[string]Summary{
	"os/exec.Command":       TwoArgPropagation,
	"(*os/exec.Cmd).Output": SingleVarArgPropagation,
	// func (*exec.Cmd).Start() error
	"(*os/exec.Cmd).Start": SingleVarArgPropagation,
	//func (*exec.Cmd).Wait() error
	"(*os/exec.Cmd).Wait": SingleVarArgPropagation,
	// func (*exec.Cmd).Run() error
	"(*os/exec.Cmd).Run": SingleVarArgPropagation,
	// func (fs.FileInfo).Mode() fs.FileMode
	"(*os.fileStat).Mode": SingleVarArgPropagation,
	"(*os.fileStat).Name": SingleVarArgPropagation,
	"(*os.File).Close":    SingleVarArgPropagation,
	"(*os.File).Fd":       SingleVarArgPropagation,
	// func (*os.File).Readdir(n int) ([]fs.FileInfo, error)
	"(*os.File).Readdir": {
		[][]int{{0}, {1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// func (*os.File).Stat() (fs.FileInfo, error)
	"(*os.File).Stat": {
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	//func (*os.File).Write(b []byte) (n int, err error)
	"(*os.File).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*os.File).WriteAt": {
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{0}, {0}, {0}},
	},
	"(*os.File).WriteString": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (f *File) Seek(offset int64, whence int) (ret int64, err error)
	"(*os.File).Seek": {
		[][]int{{}, {0}, {0}},
		[][]int{{0}, {0}, {0}},
	},
	// func Create(name string) (*File, error)
	"os.Create": SingleVarArgPropagation,
	"os.Exit":   NoDataFlowPropagation,
	"os.Expand": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func Getenv
	"os.Getenv":     SingleVarArgPropagation,
	"os.Getpid":     NoDataFlowPropagation,
	"os.Hostname":   NoDataFlowPropagation,
	"os.IsExist":    SingleVarArgPropagation,
	"os.IsNotExist": SingleVarArgPropagation,
	// func MkdirAll(path string, perm FileMode) error
	"os.MkdirAll": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func Open(name string) (*File, error)
	"os.Open": SingleVarArgPropagation,
	// func OpenFile(name string, flag int, perm FileMode) (*File, error)
	"os.OpenFile": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func ReadDir(name string) ([]DirEntry, error)
	"os.ReadDir": SingleVarArgPropagation,
	// func Remove(name string) error {
	"os.Remove":           SingleVarArgPropagation,
	"os.RemoveAll":        SingleVarArgPropagation,
	"os.Rename":           {[][]int{{0}, {0, 1}}, [][]int{{0}, {0}}},
	"os.Stat":             SingleVarArgPropagation,
	"(*os.fileStat).Size": SingleVarArgPropagation,
	// func (f *File) ReadAt(b []byte, off int64) (n int, err error)
	"(*os.File).ReadAt": {
		[][]int{{0, 1}, {1}, {2}},
		[][]int{{0, 1}, {0, 1}, {0, 1}},
	},
}

var SummaryPath = map[string]Summary{
	// func Join(elem ...string) string
	"path.Join":           SingleVarArgPropagation,
	"path.Base":           SingleVarArgPropagation,
	"path.Clean":          SingleVarArgPropagation,
	"path/filepath.Base":  SingleVarArgPropagation,
	"path/filepath.Clean": SingleVarArgPropagation,
	"path/filepath.Dir":   SingleVarArgPropagation,
	"path/filepath.IsAbs": SingleVarArgPropagation,
	"path/filepath.Join":  SingleVarArgPropagation,
	"path/filepath.Match": {
		[][]int{{0}, {1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"path/filepath.Rel": {[][]int{{0}, {1}}, [][]int{{0}, {0}}},
}

var SummaryPlugin = map[string]Summary{}

var SummaryReflect = map[string]Summary{
	"reflect.DeepEqual": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func Indirect(v Value) Value
	"reflect.Indirect": SingleVarArgPropagation,
	// func MakeMap(typ Type) Value {
	"reflect.MakeMap": SingleVarArgPropagation,
	"reflect.MakeSlice": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	"reflect.New":     SingleVarArgPropagation,
	"reflect.TypeOf":  SingleVarArgPropagation,
	"reflect.ValueOf": SingleVarArgPropagation,
	"reflect.Zero":    SingleVarArgPropagation,
	"(reflect.Type).Kind": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (tag StructTag) Get(key string) string
	"(reflect.StructTag).Get": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(reflect.Value).Bool":  SingleVarArgPropagation,
	"(reflect.Value).Float": SingleVarArgPropagation,
	"(reflect.Value).Int":   SingleVarArgPropagation,
	// func (v Value) Elem() Value
	"(reflect.Value).Elem": SingleVarArgPropagation,
	// func (v Value) Field(i int) Value
	"(reflect.Value).Field": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) FieldByName(name string) Value
	"(reflect.Value).FieldByName": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) FieldByIndex(index int) Value
	"(reflect.Value).FieldByIndex": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) Index(i int) Value
	"(reflect.Value).Index": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) Interface() any
	"(reflect.Value).Interface": SingleVarArgPropagation,
	// func (v Value) IsNil() bool
	"(reflect.Value).IsNil": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (v Value) IsValid() bool
	"(reflect.Value).IsValid": SingleVarArgPropagation,
	// func (v Value) Kind() Kind
	"(reflect.Value).Kind": SingleVarArgPropagation,
	// func (v Value) Len() int
	"(reflect.Value).Len": SingleVarArgPropagation,
	// func (v Value) NumField() int
	"(reflect.Value).NumField": SingleVarArgPropagation,
	// func (v Value) MapKeys() []Value
	"(reflect.Value).MapKeys": SingleVarArgPropagation,
	// func (v Value) MapIndex(key) []Value
	"(reflect.Value).MapIndex": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) Set(x Value)
	"(reflect.Value).Set": {
		[][]int{{0}, {0, 1}},
		[][]int{{}, {}},
	},
	// func (v Value) SetMapIndex(key, elem Value)
	"(reflect.Value).SetMapIndex(key, elem Value)": {
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{}, {}, {}},
	},
	"(reflect.Value).String": SingleVarArgPropagation,
	// func (v Value) Type() Type
	"(reflect.Value).Type": {
		[][]int{{0}},
		[][]int{{0}},
	},
	//
	"(*reflect.rtype).Elem": {
		[][]int{{0}},
		[][]int{{0}},
	},
}

var SummaryRegexp = map[string]Summary{
	"regexp.Compile": SingleVarArgPropagation,
	// matching regexp doesn't taint arguments but either taints return
	"regexp.MatchString": {[][]int{}, [][]int{{0}, {0}}},
	"regexp.MatchReader": {[][]int{}, [][]int{{0}, {0}}},
	"regexp.MustCompile": SingleVarArgPropagation,
	"(*regexp.Regexp).Match": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (*regexp.Regexp).FindAllStringSubmatch(s string, n int) [][]string
	"(*regexp.Regexp).FindAllStringSubmatch": {
		[][]int{{0}, {0}, {0}},
		[][]int{{0}, {0}, {0}},
	},
	//func (re *Regexp) FindString(s string) string
	"(*regexp.Regexp).FindString": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (re *Regexp) MatchString(s string) bool
	"(*regexp.Regexp).MatchString": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (re *Regexp) FindAllString(s string, n int) []string
	"(*regexp.Regexp).FindAllString": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (re *Regexp) FindStringSubmatch(s string) []string
	"(*regexp.Regexp).FindStringSubmatch": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func(s string, n int) []string
	"(*regexp.Regexp).Split": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
}

var SummaryRuntime = map[string]Summary{
	"runtime.NumCPU": NoDataFlowPropagation,
	"runtime.Caller": NoDataFlowPropagation,
	// func runtime.FuncForPC(pc uintptr) *runtime.Func
	"runtime.FuncForPc":   SingleVarArgPropagation,
	"runtime/debug.init":  NoDataFlowPropagation,
	"runtime/debug.Stack": NoDataFlowPropagation,
	// func (*runtime.Func).Name() string
	"(*runtime.Func).Name": SingleVarArgPropagation,
	"runtime.init":         NoDataFlowPropagation,
}

var SummarySort = map[string]Summary{
	// func Strings(x []string)
	"sort.Strings": {
		[][]int{{0}},
		[][]int{{}},
	},
}

var SummaryStrConv = map[string]Summary{
	"strconv.init": NoDataFlowPropagation,
	"strconv.Atoi": {[][]int{{0}}, [][]int{{0}}},
	// func AppendFloat(dst []byte, f float64, fmt byte, prec, bitSize int) []byte
	"strconv.AppendFloat": {
		[][]int{{0}, {0, 1}, {0, 2}, {0, 3}},
		[][]int{{0}, {0}, {0}, {0}},
	},
	"strconv.Itoa":        {[][]int{{0}}, [][]int{{0}}},
	"strconv.FormatBool":  SingleVarArgPropagation,
	"strconv.FormatInt":   {[][]int{{0}, {1}}, [][]int{{0}, {0}}},
	"strconv.FormatFloat": {[][]int{{0}, {1}, {2}, {3}}, [][]int{{0}, {0}, {0}, {0}}},
	// func ParseBool(str string) (bool, error)
	"strconv.ParseBool": {[][]int{{0}}, [][]int{{0}}},
	// func(s string, base int, bitSize int) (i int64, err error)
	"strconv.ParseInt": {[][]int{{0}, {1}, {2}}, [][]int{{0}, {0}, {0}}},
	// func ParseFloat(s string, bitSize int) (float64, error)
	"strconv.ParseFloat": {[][]int{{0}, {1}, {2}}, [][]int{{0}, {0}, {0}}},
	// func Quote(s string) string
	"strconv.Quote": SingleVarArgPropagation,
	// func Unquote(s string) (string, error)
	"strconv.Unquote": {
		[][]int{{0}},
		[][]int{{0}},
	},
}

var SummaryStrings = map[string]Summary{
	// func Contains(s, substr string) bool {
	"strings.Contains": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func Clone(s string) string
	"strings.Clone": SingleVarArgPropagation,
	// func Compare(a, b string) int
	"strings.Compare": TwoArgPropagation,
	// func Count(s, substr string) int {
	"strings.Count": TwoArgPropagation,
	// func EqualFold(s, t string) bool {
	"strings.EqualFold": TwoArgPropagation,
	// func HasPrefix(s, prefix string) bool {
	"strings.HasPrefix": TwoArgPropagation,
	// func HasSuffix(s, prefix string) bool {
	"strings.HasSuffix": TwoArgPropagation,
	// func Index(s, substr string) int
	"strings.Index": TwoArgPropagation,
	// func IndexAny(s, chars string) int {
	"strings.IndexAny": TwoArgPropagation,
	// func IndexByte(s string, c byte) int {
	"strings.IndexByte": TwoArgPropagation,
	// func Join(elems []string, sep string) string {
	"strings.Join": {
		[][]int{{0}, {1}},
		[][]int{{0}, {1}},
	},
	// func LastIndex(s string, substr string) int
	"strings.LastIndex": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func NewReader(s string) *Reader
	"strings.NewReader": {
		[][]int{{}},
		[][]int{{0}}, // input taints output
	},
	// func Replace(s, old, new string, n int) string {
	"strings.Replace": {
		[][]int{{0}, {1}, {2}, {3}},
		[][]int{{0}, {0}, {0}, {0}},
	},
	// func ReplaceAll(s, old, new string) string {
	"strings.ReplaceAll": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func Repeat(s string, count int) string {
	"strings.Repeat": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func SplitAfterN(s string, sep string, n int) []string
	"strings.SplitAfterN": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func SplitN(s, sep string, n int) []string
	"strings.SplitN": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func Split(s, sep string) []string
	"strings.Split": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func TrimFunc(s string, f func(rune) bool) string {
	"strings.TrimFunc": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func TrimPrefix(s, prefix string) string {
	"strings.TrimPrefix": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func TrimRight(s, cutset string) string
	"strings.TrimRight": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func TrimSuffix(s, suffix string) string {
	"strings.TrimSuffix": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func ToLower(s string) string {
	"strings.ToLower": SingleVarArgPropagation,
	"strings.ToUpper": SingleVarArgPropagation,
	//func TrimSpace(s string) string
	"strings.TrimSpace": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (r *Reader) Len() int
	"(*strings.Reader).Len": {
		[][]int{{}},
		[][]int{{0}}, // receiver taints output
	},
	// func (r *Reader) Read(b []byte) (n int, err error)
	"(*strings.Reader).Read": {
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	// func (r *Reader) ReadAt(b []byte, off int64) (n int, err error)
	"(*strings.Reader).ReadAt": {
		[][]int{{1}, {}, {}},
		[][]int{{0}, {}, {0}},
	},
	// func (r *Reader) ReadByte() (byte, error)
	"(*strings.Reader).ReadByte": {
		[][]int{{}},
		[][]int{{0}},
	},
	// func (r *Reader) ReadRune() (ch rune, size int, err error)
	"(*strings.Reader).ReadRune": {
		[][]int{{}},
		[][]int{{0}},
	},
	// func (r *Reader) Seek(offset int64, whence int) (int64, error)
	"(*strings.Reader).Seek": {
		[][]int{{}, {0}, {0}}, // inputs taint the receiver (state change)
		[][]int{{0}, {0}, {0}},
	},
}

var SummarySync = map[string]Summary{
	"sync/atomic.LoadUint32": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func StoreInt32(addr *int32, val int32)
	" sync/atomic.StoreInt32": {
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func StoreInt64(addr *int64, val int64)
	" sync/atomic.StoreInt64": {
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func StoreUint32(addr *uint32, val uint32)
	"sync/atomic.StoreUint32": {
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func StoreUint64(addr *uint64, val uint64)
	" sync/atomic.StoreUint64": {
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func (v *Value) Load() (val any)
	"(*sync/atomic.Value).Load": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (v *Value) Store(val any)
	"(*sync/atomic.Value).Store": {
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func (v *Value) Swap(new any) (old any)
	"(*sync/atomic.Value).Swap": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {}},
	},
	"(*sync.Once).Do": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(*sync.Map).Load":   SingleVarArgPropagation,
	"(*sync.Map).Delete": SingleVarArgPropagation,
	"(*sync.Mutex).Unlock": {
		[][]int{{0}},
		[][]int{{}},
	},
	"(*sync.Mutex).Lock": {
		[][]int{{0}},
		[][]int{{}},
	},
	// func (rw *RWMutex) Lock()
	"(*sync.RWMutex).Lock": NoDataFlowPropagation,
	// func (rw *RWMutex) RLock()
	"(*sync.RWMutex).RLock": NoDataFlowPropagation,
	//func (rw *RWMutex) RLocker() Locker
	"(*sync.RWMutex).RLocker": {
		[][]int{{}},
		[][]int{{0}}, // receiver taints output
	},
	// func (rw *RWMutex) RUnlock()
	"(*sync.RWMutex).RUnlock": NoDataFlowPropagation,
	// func (rw *RWMutex) TryLock() bool
	"(*sync.RWMutex).TryLock": {
		[][]int{{}},
		[][]int{{0}}, // receiver taints output
	},
	// func (rw *RWMutex) Unlock()
	"(*sync.RWMutex).Unlock": NoDataFlowPropagation,
	// func (*WaitGroup) Add(int)
	"(*sync.WaitGroup).Add": NoDataFlowPropagation,
	// func (wg *WaitGroup) Done()
	"(*sync.WaitGroup).Done": NoDataFlowPropagation,
	// func (wg *WaitGroup) Wait()
	"(*sync.WaitGroup).Wait": NoDataFlowPropagation,
}

var SummarySyscall = map[string]Summary{
	"syscall.Getuid": NoDataFlowPropagation,
}

var SummaryTesting = map[string]Summary{}

var SummaryText = map[string]Summary{}

var SummaryTime = map[string]Summary{
	"time.After":  SingleVarArgPropagation,
	"time.Before": SingleVarArgPropagation,
	// func Parse(layout, value string) (Time, error)
	"time.Parse": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func ParseInLocation(layout string, value string, loc *Location) (Time, error
	"time.ParseInLocation": {
		[][]int{{0}, {1}, {2}},
		[][]int{{0, 1}, {0, 1}, {0, 1}},
	},
	// func Sleep(d Duration)
	"time.Sleep": {
		[][]int{{0}},
		[][]int{},
	},
	"time.NewTimer": SingleVarArgPropagation,
	"time.Now":      NoDataFlowPropagation,
	"time.Since":    SingleVarArgPropagation,
	// func Unix(sec int64, nsec int64) Time
	"time.Unix": {
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(time.Duration).Seconds": SingleVarArgPropagation,
	"(time.Duration).Hours":   SingleVarArgPropagation,
	"(time.Duration).Days":    SingleVarArgPropagation,
	// func Until(t Time) Duration
	"time.Until":          SingleVarArgPropagation,
	"(*time.Ticker).Stop": SingleVarArgPropagation,
	// func (t Time) Add(d Duration) Time
	"(time.Time).Add": TwoArgPropagation,
	// func (t Time) After(d Duration) Time
	"(time.Time).After": TwoArgPropagation,
	// func (t Time) Before(d Duration) Time
	"(time.Time).Before": TwoArgPropagation,
	"(time.Time).Day":    SingleVarArgPropagation,
	// func (t Time) IsZero() Time
	"(time.Time).IsZero": SingleVarArgPropagation,
	"(time.Time).Equal":  TwoArgPropagation,
	// func (t Time) Format(layout string) string
	"(time.Time).Format": TwoArgPropagation,
	"(time.Time).Month":  SingleVarArgPropagation,
	"(time.Time).Second": SingleVarArgPropagation,
	"(time.Time).Sub":    TwoArgPropagation,
	// func (t Time) UTC() Time
	"(time.Time).UTC": SingleVarArgPropagation,
	// func (t Time) UnixNano() int64
	"(time.Time).UnixNano": SingleVarArgPropagation,
	"(time.Time).Unix":     SingleVarArgPropagation,
	"(time.Time).Year":     SingleVarArgPropagation,
	// func (*time.Timer).Stop() bool
	"(*time.Timer).Stop": SingleVarArgPropagation,
}

var SummaryUnicode = map[string]Summary{
	"unicode.IsSpace":          SingleVarArgPropagation,
	"unicode/utf8.ValidString": SingleVarArgPropagation,
}

var SummaryUnsafe = map[string]Summary{}

var SummaryInternal = map[string]Summary{}
