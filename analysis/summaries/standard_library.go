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
	"archive/tar":                 summaryArchiveTar,
	"archive/zip":                 summaryArchiveZip,
	"bufio":                       summaryBufIo,
	"builtin":                     summaryBuiltin,
	"bytes":                       summaryBytes,
	"compress/bzip2":              summaryCompressBzip2,
	"compress/flate":              summaryCompressFlate,
	"compress/gzip":               summaryCompressGzip,
	"compress/lzw":                summaryCompressLzw,
	"compress/zlib":               summaryCompressZlib,
	"container":                   summaryContainer,
	"container/heap":              summaryContainer,
	"container/list":              summaryContainer,
	"context":                     summaryContext,
	"crypto":                      summaryCrypto,
	"crypto/aes":                  summaryCrypto,
	"crypto/cipher":               summaryCrypto,
	"crypto/des":                  summaryCrypto,
	"crypto/ecdsa":                summaryCrypto,
	"crypto/elliptic":             summaryCrypto,
	"crypto/hmac":                 summaryCrypto,
	"crypto/internal":             summaryCrypto,
	"crypto/internal/boring":      summaryCrypto,
	"crypto/internal/nistec":      summaryCrypto,
	"crypto/internal/nistec/fiat": summaryCrypto,
	"crypto/rand":                 summaryCrypto,
	"crypto/rsa":                  summaryCrypto,
	"crypto/sha1":                 summaryCrypto,
	"crypto/tls":                  summaryCrypto,
	"crypto/x509":                 summaryCrypto,
	"database":                    summaryDatabase,
	"debug":                       summaryDebug,
	"embed":                       summaryEmbed,
	"encoding":                    summaryEncoding,
	"encoding/asn1":               summaryEncoding,
	"encoding/base64":             summaryEncoding,
	"encoding/gob":                summaryEncoding,
	"encoding/binary":             summaryEncoding,
	"encoding/json":               summaryEncoding,
	"encoding/xml":                summaryEncoding,
	"errors":                      summaryErrors,
	"expvar":                      summaryExpVar,
	"flag":                        summaryFlag,
	"fmt":                         summaryFmt,
	"go":                          summaryGo,
	"hash":                        summaryHash,
	"html":                        summaryHtml,
	"image":                       summaryImage,
	"image/color":                 summaryImage,
	"index":                       summaryIndex,
	"io":                          summaryIo,
	"io/fs":                       summaryIo,
	"io/ioutil":                   summaryIo,
	"log":                         summaryLog,
	"maps":                        summaryMaps,
	"math":                        summaryMath,
	"math/big":                    summaryMath,
	"math/bits":                   summaryMath,
	"math/cmplx":                  summaryMath,
	"math/rand":                   summaryMath,
	"mime":                        summaryMime,
	"net":                         summaryNet,
	"net/http":                    summaryNet,
	"net/netip":                   summaryNet,
	"net/textproto":               summaryNet,
	"net/url":                     summaryNet,
	"os":                          summaryOs,
	"os/exec":                     summaryOs,
	"path":                        summaryPath,
	"path/filepath":               summaryPath,
	"plugin":                      summaryPlugin,
	"reflect":                     summaryReflect,
	"regexp":                      summaryRegexp,
	"regexp/syntax":               summaryRegexp,
	"runtime":                     summaryRuntime,
	"runtime/debug":               summaryRuntime,
	"sort":                        summarySort,
	"strconv":                     summaryStrConv,
	"strings":                     summaryStrings,
	"sync":                        summarySync,
	"sync/atomic":                 summarySync,
	"syscall":                     summarySyscall,
	"syscall/js":                  summarySyscall,
	"testing":                     summaryTesting,
	"text":                        summaryText,
	"time":                        summaryTime,
	"unicode":                     summaryUnicode,
	"unicode/utf8":                summaryUnicode,
	"unsafe":                      summaryUnsafe,

	// Internal

	"internal":                 summaryInternal,
	"internal/abi":             summaryInternal,
	"internal/bisect":          summaryInternal,
	"internal/buildcfg":        summaryInternal,
	"internal/bytealg":         summaryInternal,
	"internal/cfg":             summaryInternal,
	"internal/cpu":             summaryInternal,
	"internal/diff":            summaryInternal,
	"internal/fmtsort":         summaryInternal,
	"internal/fuzz":            summaryInternal,
	"internal/goarch":          summaryInternal,
	"internal/godebug":         summaryInternal,
	"internal/goexperiment":    summaryInternal,
	"internal/goos":            summaryInternal,
	"internal/goroot":          summaryInternal,
	"internal/intern":          summaryInternal,
	"internal/itoa":            summaryInternal,
	"internal/lazyregexp":      summaryInternal,
	"internal/lazytemplate":    summaryInternal,
	"internal/nettrace":        summaryInternal,
	"internal/obscuretestdata": summaryInternal,
	"internal/oserror":         summaryInternal,
	"internal/poll":            summaryInternal,
	"internal/race":            summaryInternal,
	"internal/reflectlite":     summaryInternal,
	"internal/syscall":         summaryInternal,
	"internal/syscall/execenv": summaryInternal,
	"internal/syscall/unix":    summaryInternal,
	"internal/syscall/windows": summaryInternal,
	"internal/testlog":         summaryInternal,
	"internal/unsafeheader":    summaryInternal,
}

var summaryArchiveTar = map[string]Summary{}

var summaryArchiveZip = map[string]Summary{}

var summaryBufIo = map[string]Summary{
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

var summaryBuiltin = map[string]Summary{}

var summaryBytes = map[string]Summary{
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

var summaryCompressBzip2 = map[string]Summary{}

var summaryCompressFlate = map[string]Summary{}

var summaryCompressGzip = map[string]Summary{}

var summaryCompressLzw = map[string]Summary{}

var summaryCompressZlib = map[string]Summary{}

var summaryContainer = map[string]Summary{}

var summaryContext = map[string]Summary{}

var summaryCrypto = map[string]Summary{
	"crypto/aes.NewCipher": SingleVarArgPropagation,
	"crypto/cipher.NewGCM": SingleVarArgPropagation,
	// func (cipher.AEAD) Seal(dst []byte, nonce []byte, plaintext []byte, additionalData []byte) []byte
	"(crypto/cipher.AEAD).Seal": SingleVarArgPropagation,
	"(*crypto/cipher.gcm).Seal": SingleVarArgPropagation,
	"(*crypto/aes.gcmAsm).Seal": SingleVarArgPropagation,
	"crypto/hmac.New":           TwoArgPropagation,
	"(*crypto/hmac.hmac).Sum":   SingleVarArgPropagation,
	// func (io.Writer) Write(p []byte) (n int, err error)
	"(*crypto/hmac.hmac).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{},
	},
	"crypto/sha256.New":                SingleVarArgPropagation,
	"crypto/tls.X509KeyPair":           TwoArgPropagation,
	"crypto/x509.NewCertPool":          NoDataFlowPropagation,
	"crypto/x509.MarshalPKIXPublicKey": SingleVarArgPropagation,
	"crypto/x509.ParsePKCS1PrivateKey": SingleVarArgPropagation,
	"crypto/x509.SystemCertPool":       NoDataFlowPropagation,
	"crypto/sha256.blockGeneric":       NoDataFlowPropagation,
	"(crypto.Hash).New":                SingleVarArgPropagation,
	"(*crypto/tls.Config).Clone":       SingleVarArgPropagation,
	"(*crypto/x509.CertPool).AppendCertsFromPEM": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func Read(b []byte) (n int, err error)
	"crypto/Rand.Read": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func GenerateKey(random io.Reader, bits int) (*PrivateKey, error)
	"crypto/rsa.GenerateKey": TwoArgPropagation,
	// func GenerateKey(curve Curve, rand io.Reader) (priv []byte, x, y *big.Int, err error)
	"crypto/elliptic.GenerateKey": {
		[][]int{{0}, {0}},
		[][]int{{0, 1, 2}, {0, 1, 2}},
	},
	// func elliptic.MarshalCompressed(curve elliptic.Curve, x *big.Int, y *big.Int) []byte
	"crypto/elliptic.MarshalCompressed": {
		[][]int{{0}},
		[][]int{{0}, {0}, {0}},
	},
}

var summaryDatabase = map[string]Summary{}

var summaryDebug = map[string]Summary{}

var summaryEmbed = map[string]Summary{}

var summaryEncoding = map[string]Summary{
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
	// func (*base64.Encoding).EncodeToString(src []byte) string
	"(*encoding/base64.Encoding).EncodeToString": TwoArgPropagation,
	// func (*base64.Encoding) DecodeString(s string) ([]byte, error)
	"(*encoding/base64.Encoding).DecodeString": TwoArgPropagation,
}

var summaryErrors = map[string]Summary{
	"errors.New": SingleVarArgPropagation,
}

var summaryExpVar = map[string]Summary{}

var summaryFlag = map[string]Summary{
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

var summaryFmt = map[string]Summary{
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
	"fmt.Errorf": FormatterPropagation,
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
	"fmt.Sprint": SingleVarArgPropagation,
	//func Sprintf(format string, a ...any) string
	"fmt.Sprintf": FormatterPropagation,
	// func Printf(format string, a ...any) (n int, err error)
	"fmt.Printf": FormatterPropagation,
}

var summaryGo = map[string]Summary{}

var summaryHash = map[string]Summary{
	"hash/Hash.Sum": TwoArgPropagation,
}

var summaryHtml = map[string]Summary{}

var summaryImage = map[string]Summary{}

var summaryIndex = map[string]Summary{}

var summaryIo = map[string]Summary{
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
	"(*io.PipeWriter).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
}

var summaryLog = map[string]Summary{
	"log.Debugf": {[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
	"log.Printf": {[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
	"log.Fatal":  {[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
	// func (l *Logger) Printf(v ...any)
	"(*log.Logger).Print": {
		[][]int{{0}},
		[][]int{{}, {}, {}},
	},
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

var summaryMaps = map[string]Summary{
	"maps.clone": SingleVarArgPropagation,
}

var summaryMath = map[string]Summary{
	"math.init":           NoDataFlowPropagation,
	"math.Abs":            SingleVarArgPropagation,
	"math.IsNaN":          SingleVarArgPropagation,
	"math.IsInf":          SingleVarArgPropagation,
	"math.Log2":           SingleVarArgPropagation,
	"math.Max":            TwoArgPropagation,
	"math.Min":            TwoArgPropagation,
	"math.Mod":            TwoArgPropagation,
	"math.Modf":           SingleVarArgPropagation,
	"math.Pow":            TwoArgPropagation,
	"math.Pow10":          SingleVarArgPropagation,
	"math.Round":          SingleVarArgPropagation,
	"math.RoundToEven":    SingleVarArgPropagation,
	"math/big.init":       NoDataFlowPropagation,
	"math/rand.init":      NoDataFlowPropagation,
	"math/rand.Int":       NoDataFlowPropagation,
	"math/rand.Intn":      NoDataFlowPropagation,
	"math/rand.New":       SingleVarArgPropagation,
	"math/rand.NewSource": SingleVarArgPropagation,
	"math/rand.Seed":      NoDataFlowPropagation,
	"math/rand.Float32":   NoDataFlowPropagation,
	// func (z *big.Int) Exp(x *big.Int, y *big.Int, m *big.Int) *big.Int
	"(*math/big.Int).Exp": {
		[][]int{{0}, {0, 1}, {0, 2}, {0, 3}},
		[][]int{{0}, {0}, {0}, {0}},
	},
	// func (z *big.Int) SetBytes(buf []byte) *big.Int
	"(*math/big.Int).SetBytes": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (x *big.Int) FillBytes(buf []byte) []byte
	"(*math/big.Int).FillBytes": {
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
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

var summaryMime = map[string]Summary{}

var summaryNet = map[string]Summary{
	"net.init": NoDataFlowPropagation,
	"net.Close": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func Dial(network, address string) (Conn, error) {
	"net.Dial": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func Listen(network, address string) (Listener, error)
	"net.Listen": {
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func SplitHostPort(hostport string) (host, port string, err error)
	"net.SplitHostPort": {
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (l *UnixListener) Accept() (Conn, error)
	"(*net.UnixListener).Accept": {
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func (l *UnixListener) Close() error
	"(*net.UnixListener).Close": {
		[][]int{{0}},
		[][]int{{}},
	},
	"(*net.netFD).Read": {
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	"(*net.conn).Read": {
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	"(*net.conn).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*net.conn).Close": {
		[][]int{{0}},
		[][]int{{}},
	},
	// func (c *UnixConn) Read(b []byte) (int, error)
	"(*net.UnixConn).Read": {
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	"(*net.UnixConn).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// func (l *TCPListener) Accept() (Conn, error)
	"(*net.TCPListener).Accept": {
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func (l *TCPListener) Close() error
	"(*net.TCPListener).Close": {
		[][]int{{0}},
		[][]int{{}},
	},
	// func (c *TCPConn) Read(b []byte) (int, error)
	"(*net.TCPConn).Read": {
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	"(*net.TCPConn).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*net.UDPConn).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*net.IPConn).Write": {
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
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
	// func Parse(rawURL string) (*URL, error)
	"net/url.Parse": {
		[][]int{{}},
		[][]int{{0, 1}, {0, 1}},
	},
}

var summaryOs = map[string]Summary{
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
	"os.ReadDir":  SingleVarArgPropagation,
	"os.ReadFile": SingleVarArgPropagation,
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

var summaryPath = map[string]Summary{
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

var summaryPlugin = map[string]Summary{}

var summaryReflect = map[string]Summary{
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

var summaryRegexp = map[string]Summary{
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

var summaryRuntime = map[string]Summary{
	"runtime.NumCPU": NoDataFlowPropagation,
	"runtime.Caller": NoDataFlowPropagation,
	// func runtime.FuncForPC(pc uintptr) *runtime.Func
	"runtime.FuncForPc":   SingleVarArgPropagation,
	"runtime/debug.init":  NoDataFlowPropagation,
	"runtime/debug.Stack": NoDataFlowPropagation,
	// func (*runtime.Func).Name() string
	"(*runtime.Func).Name": SingleVarArgPropagation,
	"runtime.init":         NoDataFlowPropagation,
	"runtime.clone":        SingleVarArgPropagation,
}

var summarySort = map[string]Summary{
	// func Strings(x []string)
	"sort.Strings": {
		[][]int{{0}},
		[][]int{{}},
	},
}

var summaryStrConv = map[string]Summary{
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

var summaryStrings = map[string]Summary{
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

var summarySync = map[string]Summary{
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

var summarySyscall = map[string]Summary{
	"syscall.Getuid": NoDataFlowPropagation,
}

var summaryTesting = map[string]Summary{}

var summaryText = map[string]Summary{}

var summaryTime = map[string]Summary{
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
	"(time.Time).Format":     TwoArgPropagation,
	"(time.Time).Month":      SingleVarArgPropagation,
	"(time.Time).Hour":       SingleVarArgPropagation,
	"(time.Time).Minute":     SingleVarArgPropagation,
	"(time.Time).Second":     SingleVarArgPropagation,
	"(time.Time).Nanosecond": SingleVarArgPropagation,
	"(time.Time).Sub":        TwoArgPropagation,
	// func (t Time) UTC() Time
	"(time.Time).UTC": SingleVarArgPropagation,
	// func (t Time) UnixNano() int64
	"(time.Time).UnixNano": SingleVarArgPropagation,
	"(time.Time).Unix":     SingleVarArgPropagation,
	"(time.Time).Year":     SingleVarArgPropagation,
	// func (*time.Timer).Stop() bool
	"(*time.Timer).Stop": SingleVarArgPropagation,
}

var summaryUnicode = map[string]Summary{
	"unicode.IsSpace":          SingleVarArgPropagation,
	"unicode/utf8.ValidString": SingleVarArgPropagation,
}

var summaryUnsafe = map[string]Summary{}

var summaryInternal = map[string]Summary{}
