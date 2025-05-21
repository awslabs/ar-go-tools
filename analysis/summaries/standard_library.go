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
var stdPackages = map[string]map[string]Summarizer{
	"archive/tar":                    summaryArchiveTar,
	"archive/zip":                    summaryArchiveZip,
	"bufio":                          summaryBufIo,
	"builtin":                        summaryBuiltin,
	"bytes":                          summaryBytes,
	"compress/bzip2":                 summaryCompressBzip2,
	"compress/flate":                 summaryCompressFlate,
	"compress/gzip":                  summaryCompressGzip,
	"compress/lzw":                   summaryCompressLzw,
	"compress/zlib":                  summaryCompressZlib,
	"container":                      summaryContainer,
	"container/heap":                 summaryContainer,
	"container/list":                 summaryContainer,
	"context":                        summaryContext,
	"crypto":                         summaryCrypto,
	"crypto/aes":                     summaryCrypto,
	"crypto/cipher":                  summaryCrypto,
	"crypto/des":                     summaryCrypto,
	"crypto/ecdsa":                   summaryCrypto,
	"crypto/elliptic":                summaryCrypto,
	"crypto/internal":                summaryCrypto,
	"crypto/internal/boring":         summaryCrypto,
	"crypto/internal/fips140/aes":    summaryCrypto,
	"crypto/internal/fips140/sha3":   summaryCrypto,
	"crypto/internal/fips140/sha256": summaryCrypto,
	"crypto/internal/fips140/sha512": summaryCrypto,
	"crypto/internal/nistec":         summaryCrypto,
	"crypto/internal/nistec/fiat":    summaryCrypto,
	"crypto/md5":                     summaryCrypto,
	"crypto/hkdf":                    summaryCrypto,
	"crypto/mlkem":                   summaryCrypto,
	"crypto/pbkdf2":                  summaryCrypto,
	"crypto/rand":                    summaryCrypto,
	"crypto/rsa":                     summaryCrypto,
	"crypto/sha1":                    summaryCrypto,
	"crypto/sha3":                    summaryCrypto,
	"crypto/sha256":                  summaryCrypto,
	"crypto/sha512":                  summaryCrypto,
	"crypto/tls":                     summaryCrypto,
	"crypto/x509":                    summaryCrypto,
	"database":                       summaryDatabase,
	"debug":                          summaryDebug,
	"embed":                          summaryEmbed,
	"encoding":                       summaryEncoding,
	"encoding/asn1":                  summaryEncoding,
	"encoding/base64":                summaryEncoding,
	"encoding/csv":                   summaryEncodingCsv,
	"encoding/hex":                   summaryEncoding,
	"encoding/gob":                   summaryEncoding,
	"encoding/binary":                summaryEncoding,
	"encoding/json":                  summaryEncoding,
	"encoding/xml":                   summaryEncoding,
	"errors":                         summaryErrors,
	"expvar":                         summaryExpVar,
	"flag":                           summaryFlag,
	"fmt":                            summaryFmt,
	"go":                             summaryGo,
	"hash":                           summaryHash,
	"hash/adler32":                   summaryHash,
	"hash/crc32":                     summaryHash,
	"hash/crc64":                     summaryHash,
	"hash/fnv":                       summaryHash,
	"hash/maphash":                   summaryHash,
	"html":                           summaryHtml,
	"image":                          summaryImage,
	"image/color":                    summaryImage,
	"index":                          summaryIndex,
	"io":                             summaryIo,
	"io/fs":                          summaryIo,
	"io/ioutil":                      summaryIo,
	"log":                            summaryLog,
	"log/slog":                       summaryLog,
	"maps":                           summaryMaps,
	"math":                           summaryMath,
	"math/big":                       summaryMath,
	"math/bits":                      summaryMath,
	"math/cmplx":                     summaryMath,
	"math/rand":                      summaryMath,
	"math/rand/v2":                   summaryMath,
	"mime":                           summaryMime,
	"net":                            summaryNet,
	"net/http":                       summaryNet,
	"net/netip":                      summaryNet,
	"net/smtp":                       summaryNet,
	"net/textproto":                  summaryNet,
	"net/url":                        summaryNet,
	"os":                             summaryOs,
	"os/exec":                        summaryOs,
	"path":                           summaryPath,
	"path/filepath":                  summaryPath,
	"plugin":                         summaryPlugin,
	"reflect":                        summaryReflect,
	"regexp":                         summaryRegexp,
	"regexp/syntax":                  summaryRegexp,
	"runtime":                        summaryRuntime,
	"runtime/debug":                  summaryRuntime,
	"sort":                           summarySort,
	"strconv":                        summaryStrConv,
	"strings":                        summaryStrings,
	"sync":                           summarySync,
	"sync/atomic":                    summarySync,
	"syscall":                        summarySyscall,
	"syscall/js":                     summarySyscall,
	"testing":                        summaryTesting,
	"text":                           summaryText,
	"time":                           summaryTime,
	"unicode":                        summaryUnicode,
	"unicode/utf8":                   summaryUnicode,
	"unsafe":                         summaryUnsafe,
	"weak":                           summaryWeak,

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
	"internal/stringslite":     summaryInternal,
	"internal/syscall":         summaryInternal,
	"internal/syscall/execenv": summaryInternal,
	"internal/syscall/unix":    summaryInternal,
	"internal/syscall/windows": summaryInternal,
	"internal/testlog":         summaryInternal,
	"internal/unsafeheader":    summaryInternal,
}

var summaryArchiveTar = map[string]Summarizer{
	//  === Reader ===

	// func NewReader(r io.Reader) *Reader
	"archive/tar.NewReader": rawSummary{
		Flows: map[string][]string{
			"!arg 0": {"!ret 0"},
		},
	}.mustCompile(),
	// func (tr *Reader) Next() (*Header, error)
	"(*archive/tar.Reader).Next": rawSummary{
		Flows: map[string][]string{"!receiver": {"!ret 0", "!ret 1"}},
	}.mustCompile(),
	// func (tr *Reader) Read(b []byte) (int, error)
	"(*archive/tar.Reader).Read": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!arg 0", "!ret 0", "!ret 1"},
		},
	}.mustCompile(),

	// === Writer ===

	// func NewWriter(w io.Writer) *Writer
	"archive/tar.NewWriter": rawSummary{
		Flows: map[string][]string{"!arg 0": {"!ret 0"}},
	}.mustCompile(),
	// func (tw *Writer) AddFS(fsys fs.FS) error
	"(*archive/tar.Writer).AddFS": rawSummary{
		Flows: map[string][]string{"!arg 0": {"!receiver", "!ret 0"}},
	}.mustCompile(),
	// func (tw *Writer) Close() error
	"(*archive/tar.Writer).Close": rawSummary{
		Flows: map[string][]string{"!receiver": {"!ret 0"}},
	}.mustCompile(),
	// func (tw *Writer) Flush() error
	"(*archive/tar.Writer).Flush": rawSummary{
		Flows: map[string][]string{"!receiver": {"!ret 0"}},
	}.mustCompile(),
	// func (tw *Writer) Write(b []byte) (int, error)
	"(*archive/tar.Writer).Writer": rawSummary{
		Flows: map[string][]string{"!arg 0": {"!receiver", "!ret 0", "!ret 1"}},
	}.mustCompile(),
	// func (tw *Writer) WriteHeader(hdr *Header) error
	"(*archive/tar.Writer).WriteHeader": rawSummary{
		Flows: map[string][]string{"!arg 0": {"!receiver", "!ret 0"}},
	}.mustCompile(),
}

var summaryArchiveZip = map[string]Summarizer{}

var summaryBufIo = map[string]Summarizer{
	"bufio.NewReader":           SingleVarArgPropagation,
	"bufio.NewReaderSize":       TwoArgPropagation,
	"bufio.NewScanner":          SingleVarArgPropagation,
	"(*bufio.Reader).ReadSlice": TwoArgPropagation,
	"(*bufio.Scanner).Scan": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*bufio.Scanner).Split": TwoArgPropagation,
	"(*bufio.Scanner).Text":  SingleVarArgPropagation,
}

var summaryBuiltin = map[string]Summarizer{}

var summaryBytes = map[string]Summarizer{
	// func Equal(a, b []byte) bool {
	"bytes.Equal": TwoArgPropagation,
	// func NewBuffer(buf []byte) *Buffer
	"bytes.NewBuffer": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func NewBufferString(s string) *Buffer
	"bytes.NewBufferString": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func NewReader(b []byte) *Reader
	"bytes.NewReader": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	"bytes.Runes": SingleVarArgPropagation,
	// func (b *Buffer) Bytes() []byte
	"(*bytes.Buffer).Bytes": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	"(*bytes.Buffer).Len": SingleVarArgPropagation,
	// func (b *Buffer) String() string
	"(*bytes.Buffer).String": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (b *Buffer) Write(c) error
	"(*bytes.Buffer).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (b *Buffer) WriteByte(c byte) error
	"(*bytes.Buffer).WriteByte": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (b *Buffer) WriteRune(r rune) (n int, err error)
	"(*bytes.Buffer).WriteRune": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (b *Buffer) WriteString(s string) (n int, err error)
	"(*bytes.Buffer).WriteString": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (b *Buffer) WriteTo(w io.Writer) (n int64, err error)
	"(*bytes.Buffer).WriteTo": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (r *Reader) Seek(offset int64, whence int) (int64, error)
	"(*bytes.Reader).Seek": Summary{
		[][]int{{}, {0}, {0}},
		[][]int{{0}, {0}, {0}},
	},
}

var summaryCompressBzip2 = map[string]Summarizer{}

var summaryCompressFlate = map[string]Summarizer{}

var summaryCompressGzip = map[string]Summarizer{}

var summaryCompressLzw = map[string]Summarizer{}

var summaryCompressZlib = map[string]Summarizer{}

var summaryContainer = map[string]Summarizer{}

var summaryContext = map[string]Summarizer{}

var summaryCrypto = map[string]Summarizer{
	"crypto/aes.NewCipher": SingleVarArgPropagation,
	"crypto/cipher.NewGCM": SingleVarArgPropagation,
	// func (cipher.AEAD) Seal(dst []byte, nonce []byte, plaintext []byte, additionalData []byte) []byte
	"(crypto/cipher.AEAD).Seal": SingleVarArgPropagation,
	"(*crypto/cipher.gcm).Seal": SingleVarArgPropagation,
	"(*crypto/aes.gcmAsm).Seal": SingleVarArgPropagation,
	"crypto/hmac.New":           TwoArgPropagation,
	"(*crypto/hmac.hmac).Sum":   SingleVarArgPropagation,
	// func (io.Writer) Write(p []byte) (n int, err error)
	"(*crypto/hmac.hmac).Write": Summary{
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
	"crypto/sha256.Sum256":             SingleVarArgPropagation,
	"crypto/sha256.Sum244":             SingleVarArgPropagation,
	"crypto/sha512.Sum384":             SingleVarArgPropagation,
	"crypto/sha512.Sum512":             SingleVarArgPropagation,
	"crypto/sha512.Sum512_224":         SingleVarArgPropagation,
	"crypto/sha512.Sum512_256":         SingleVarArgPropagation,
	"crypto/sha3.Sum224":               SingleVarArgPropagation,
	"crypto/sha3.Sum256":               SingleVarArgPropagation,
	"crypto/sha3.Sum384":               SingleVarArgPropagation,
	"crypto/sha3.Sum512":               SingleVarArgPropagation,
	"crypto/md5.Sum":                   SingleVarArgPropagation,
	"(crypto.Hash).New":                SingleVarArgPropagation,
	"(*crypto/tls.Config).Clone":       SingleVarArgPropagation,
	"(*crypto/x509.CertPool).AppendCertsFromPEM": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func Read(b []byte) (n int, err error)
	"crypto/Rand.Read": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func GenerateKey(random io.Reader, bits int) (*PrivateKey, error)
	"crypto/rsa.GenerateKey": TwoArgPropagation,
	// func GenerateKey(curve Curve, rand io.Reader) (priv []byte, x, y *big.Int, err error)
	"crypto/elliptic.GenerateKey": Summary{
		[][]int{{0}, {0}},
		[][]int{{0, 1, 2}, {0, 1, 2}},
	},
	// func elliptic.MarshalCompressed(curve elliptic.Curve, x *big.Int, y *big.Int) []byte
	"crypto/elliptic.MarshalCompressed": Summary{
		[][]int{{0}},
		[][]int{{0}, {0}, {0}},
	},
}

var summaryDatabase = map[string]Summarizer{}

var summaryDebug = map[string]Summarizer{}

var summaryEmbed = map[string]Summarizer{}

var summaryEncoding = map[string]Summarizer{
	// func (enc *Encoding) Encode(dst, src []byte)
	"(*encoding/base64.Encoding).Encode": Summary{
		[][]int{{}, {1}, {1, 2}},
		[][]int{{}, {0}, {0}},
	},
	// func (enc *Encoding) AppendDecode(dst, src []byte) ([]byte, error)
	"(*encoding/base64.Encoding).AppendDecode": Summary{
		[][]int{{0}, {1}, {1, 2}},
		[][]int{{}, {0, 1}, {0, 1}},
	},
	// func (enc *Encoding) AppendEncode(dst, src []byte) []byte
	"(*encoding/base64.Encoding).AppendEncode": Summary{
		[][]int{{}, {1}, {1, 2}},
		[][]int{{}, {0}, {0}},
	},
	// func (enc *Encoding) EncodeToString(src []byte) string
	"(*encoding/base64.Encoding).EncodeToString": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (enc *Encoding) DecodeString(s string) ([]byte, error)
	"(*encoding/base64.Encoding).DecodeString": Summary{
		[][]int{{}, {1}},
		[][]int{{}, {0, 1}},
	},
	// func (enc *Encoding) Decode(dst, src []byte) (n int, err error)
	"(*encoding/base64.Encoding).Decode": Summary{
		[][]int{{0}, {1}, {1, 2}},
		[][]int{{}, {0, 1}, {0, 1}},
	},
	// func (enc Encoding) Strict() *Encoding
	"(encoding/base64).Strict": SingleVarArgPropagation,
	// func (enc Encoding) WithPadding(padding rune) *Encoding
	"(encoding/base64).WithPadding": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func EncodeToString(src []byte) string
	"encoding/hex.EncodeToString": SingleVarArgPropagation,
	"encoding/json.init":          NoDataFlowPropagation,
	// func Indent(dst *bytes.Buffer, src []byte, prefix, indent string) error
	"encoding/json.Indent": Summary{
		[][]int{{0}, {0}, {0}, {0}}, // all args taint the first
		[][]int{{}, {0}, {0}, {0}},  // all args except first taint return error
	},
	// func Marshal(v any) ([]byte, error)
	"encoding/json.Marshal": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func MarshalIndent(v any, prefix string, indent string) ([]byte, error)
	"encoding/json.MarshalIndent": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func Unmarshal(data []byte, v any) error
	"encoding/json.Unmarshal": Summary{
		[][]int{{0, 1}, {}},
		[][]int{{0}, {0}},
	},
	// func NewDecoder(r io.Reader) *Decoder
	"encoding/json.NewDecoder": SingleVarArgPropagation,
	// func (dec *Decoder) Buffered() io.Reader
	"(*encoding/json.Decoder).Buffered": SingleVarArgPropagation,
	// func (dec *Decoder) Decode(v any) error {
	"(*encoding/json.Decoder).Decode": Summary{
		[][]int{{0, 1}, {1}},
		[][]int{{0}, {0}},
	},
	"(*encoding/json.Decoder).DisallowUnknownFields": NoDataFlowPropagation,
	// func (dec *Decoder) InputOffset() int64 {
	"(*encoding/json.Decoder).InputOffset": SingleVarArgPropagation,
	// func (dec *Decoder) More() bool
	"(*encoding/json.Decoder).More": SingleVarArgPropagation,
	// func (dec *Decoder) Token() (Token, error)
	"(*encoding/json.Decoder).Token": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*encoding/json.Decoder).UseNumber": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func NewEncoder(w io.Writer) *Encoder
	"encoding/json.NewEncoder": SingleVarArgPropagation,
	// func (enc *Encoder) Encode(v any) error
	"(*encoding/json.Encoder).Encode": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (enc *Encoder) SetEscapeHTML(on bool)
	"(*encoding/json.Encoder).SetEscapeHTML": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}, {}},
	},
	// func (enc *Encoder) SetIndent(prefix, indent string)
	"(*encoding/json.Encoder).SetIndent": Summary{
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{}},
	},
	"(encoding/json.Number).Float64": SingleVarArgPropagation,
	"(encoding/json.Number).Int64":   SingleVarArgPropagation,
	"(encoding/json.Number).String":  SingleVarArgPropagation,
	// func NewDecoder(r io.Reader) *Decoder {
	"encoding/xml.NewDecoder": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	"(*encoding/xml.Decoder).Decode": TwoArgPropagation,
	// func Unmarshal(data []byte, v any) error
	"encoding/xml.Unmarshal": Summary{
		[][]int{{0, 1}, {}},
		[][]int{{0}, {0}},
	},
}

var summaryEncodingCsv = map[string]Summarizer{
	// func NewReader(r io.Reader) *Reader
	"encoding/csv.NewReader": rawSummary{
		Flows: map[string][]string{
			"!arg <r>": {"!ret"},
		},
	}.mustCompile(),
	// func NewWriter(r io.Writer) *Writer
	"encoding/csv.NewWriter": rawSummary{
		Flows: map[string][]string{
			"!arg <r>": {"!ret"},
		},
	}.mustCompile(),
	// func (e *ParseError) Error() string
	"(*encoding/csv.ParseError).Error": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!ret"},
		},
	}.mustCompile(),
	"(*encoding/csv.ParseError).Unwrap": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!ret"},
		},
	}.mustCompile(),
	"(*encoding/csv.Reader).FieldPos": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!ret 0", "!ret 1"},
		},
	}.mustCompile(),
	// func (r *Reader) InputOffset() int64
	"(*encoding/csv.Reader).InputOffset": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!ret"},
		},
	}.mustCompile(),
	// func (r *Reader) Read() (record []string, err error)
	"(*encoding/csv.Reader).Read": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!ret 0", "!ret 1"},
		},
	}.mustCompile(),
	// func (r *Reader) ReadAll() (records [][]string, err error)
	"(*encoding/csv.Reader).ReadAll": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!ret 0", "!ret 1"},
		},
	}.mustCompile(),
	// func (w *Writer) Error() error
	"(*encoding/csv.Writer).Error": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!ret"},
		},
	}.mustCompile(),
	// func (w *Writer) Flush() error
	"(*encoding/csv.Writer).Flush": rawSummary{
		Flows: map[string][]string{
			"!receiver": {"!ret"},
		},
	}.mustCompile(),
	// func (w *Writer) Write(record []string) error
	"(*encoding/csv.Writer).Write": rawSummary{
		Flows: map[string][]string{
			"!arg 0": {"!receiver", "!ret"},
		},
	}.mustCompile(),
	// func (w *Writer) WriteAll(records [][]string) error
	"(*encoding/csv.Writer).WriteAll": rawSummary{
		Flows: map[string][]string{
			"!arg 0": {"!receiver", "!ret"},
		},
	}.mustCompile(),
}

var summaryErrors = map[string]Summarizer{
	// func (e *errorString) Error() string
	"(*errors.errorString).Error": SingleVarArgPropagation,
	// func (e *joinError) Error() string
	"(*errors.joinError).Error": SingleVarArgPropagation,
	// func (e *joinError) Unwrap() []error
	"(*errors.joinError).Unwrap": SingleVarArgPropagation,
	// func (i Code) String() string
	"(internal/types/errors.Code).String": SingleVarArgPropagation,
	// func As(err error, target any) bool
	"errors.As": Summary{
		[][]int{{0, 1}, {0}},
		[][]int{{0}, {0}},
	},
	// func Is(err, target error) bool
	"errors.Is": TwoArgPropagation,
	// func Join(errs ...error) error
	"errors.Join": SingleVarArgPropagation,
	// func New(text string) error {
	"errors.New": SingleVarArgPropagation,
	// func Unwrap(err error) error
	"errors.Unwrap": SingleVarArgPropagation,
}

var summaryExpVar = map[string]Summarizer{}

var summaryFlag = map[string]Summarizer{
	//func Arg(i int) string"
	// Does not propagate data flow, unless marked as source
	"flag.Arg": NoDataFlowPropagation,
	//func Args() []string"
	"flag.Args": NoDataFlowPropagation,
	//func Bool(name string, value bool, usage string) *bool
	"flag.Bool": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func BoolVar(p *bool, name string, value bool, usage string)
	"flag.BoolVar": Summary{
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func Duration(name string, value time.Duration, usage string) *time.Duration
	"flag.Duration": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func DurationVar(p *time.Duration, name string, value time.Duration, usage string)
	"flat.DurationVar": Summary{
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func Float64(name string, value float64, usage string) *float64
	"flag.Float64": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Float64Var(p *float64, name string, value float64, usage string)
	"flag.Float64Var": Summary{
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func Int(name string, value int, usage string) *int
	"flag.Int": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Int64(name string, value int64, usage string) *int64
	"flag.Int64": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Int64Var(p *int64, name string, value int64, usage string)
	"flat.Int64Var": Summary{
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func IntVar(p *int, name string, value int, usage string)
	"flag.IntVar": Summary{
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
	"flag.String": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func StringVar(p *string, name string, value string, usage string)
	"flag.StringVar": Summary{
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func TextVar(p encoding.TextUnmarshaler, name string, value encoding.TextMarshaler, ...)
	//func Uint(name string, value uint, usage string) *uint
	"flag.Uint": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Uint64(name string, value uint64, usage string) *uint64
	"flag.Uint64": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{}, {0}, {}},
	},
	//func Uint64Var(p *uint64, name string, value uint64, usage string)
	"flag.Uint64Var": Summary{
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func UintVar(p *uint, name string, value uint, usage string)
	"flag.UintVar": Summary{
		[][]int{{0}, {1}, {0, 2}, {3}},
		[][]int{{0}, {}, {0}, {}},
	},
	//func UnquoteUsage(flag *Flag) (name string, usage string)
	//func Var(value Value, name string, usage string)
	//func Visit(fn func(*Flag))
	//func VisitAll(fn func(*Flag))
}

var summaryFmt = map[string]Summarizer{
	"fmt.init":       NoDataFlowPropagation,
	"fmt.newPrinter": NoDataFlowPropagation,
	// func Println(a ...any) (n int, err error) {
	"fmt.Println": NoDataFlowPropagation,
	// func Fprintln(w io.Writer, a ...any) (n int, err error)
	"fmt.Fprintln": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// func Errorf(format string, a ...interface{}) error
	"fmt.Errorf": FormatterPropagation,
	"fmt.Fprint": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func Fprintf(w io.Writer, format string, a ...any) (n int, err error)
	"fmt.Fprintf": Summary{
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

var summaryGo = map[string]Summarizer{}

var summaryHash = map[string]Summarizer{
	// Functions in adler32
	// func (d *digest) Reset() : no summary
	// func (d *digest) Size()
	// func (d *digest) BlockSize()
	// func (d *digest) AppendBinary(b []byte) ([]byte, error)
	"(*hash/adler32.digest).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// func (d *digest) Sum(in []byte) []byte
	"(*hash/adler32.digest).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (d *digest) Sum32() uint32
	"(*hash/adler32.digest).Sum32": SingleVarArgPropagation,
	// func Checksum(data []byte) unit32
	"hash/adler32.Checksum": SingleVarArgPropagation,
	// crc32
	"(*hash/crc32.digest).MarshalBinary": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*hash/crc32.digest).UnmarshalBinary": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*hash/crc32.digest).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*hash/crc32.digest).Sum32": SingleVarArgPropagation,
	"(*hash/crc32.digest).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"hash/crc32.ChecksumIEEE": SingleVarArgPropagation,
	"hash/crc32.Checksum":     SingleVarArgPropagation,
	// crc64
	"(*hash/crc64.digest).MarshalBinary": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*hash/crc64.digest).UnmarshalBinary": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*hash/crc64.digest).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*hash/crc64.digest).Sum64": SingleVarArgPropagation,
	"(*hash/crc64.digest).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"hash/crc64.Checksum": SingleVarArgPropagation,
	// fnv
	"(*hash/fnv.digest).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*hash/fnv.sum32).Sum32": SingleVarArgPropagation,
	"(*hash/fnv.sum64).Sum64": SingleVarArgPropagation,
	"(*hash/fnv.sum32).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum32a).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum64).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum64a).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum128).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum128a).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum32).MarshalBinary": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*hash/fnv.sum32).UnmarshalBinary": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum32a).MarshalBinary": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*hash/fnv.sum32a).UnmarshalBinary": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum64).MarshalBinary": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*hash/fnv.sum64).UnmarshalBinary": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum64a).MarshalBinary": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*hash/fnv.sum64a).UnmarshalBinary": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum128).MarshalBinary": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*hash/fnv.sum128).UnmarshalBinary": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	"(*hash/fnv.sum128a).MarshalBinary": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	"(*hash/fnv.sum128a).UnmarshalBinary": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// maphash
	"(*hash/maphash.Hash).WriteString": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// maphash
	"(*hash/maphash.Hash).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*hash/maphash.Hash).Sum64": SingleVarArgPropagation,
	"(*hash/maphash.Hash).Sum": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
}

var summaryHtml = map[string]Summarizer{}

var summaryImage = map[string]Summarizer{}

var summaryIndex = map[string]Summarizer{}

var summaryIo = map[string]Summarizer{
	// func Copy(dst Writer, src Reader) (written int64, err error)
	"io.Copy": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func CopyBuffer(dst Writer, src Reader, buf []byte) (written int64, err error)
	"io.CopyBuffer": Summary{
		[][]int{{0}, {1, 2}, {0, 2}},
		[][]int{{0}, {0}, {0}},
	},
	// func CopyN(dst Writer, src Reader, n int64) (written int64, err error)
	"io.CopyN": Summary{
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{0}, {0}, {0}},
	},
	// func ReadFull(r Reader, buf []byte) (n int, err error) {
	"io.ReadFull": Summary{
		[][]int{{0, 1}, {0}},
		[][]int{{0}, {0}},
	},
	// func TeeReader(r Reader, w Writer) Reader
	"io.TeeReader": Summary{
		[][]int{{0, 1}, {1}},
		[][]int{{0}, {}},
	},
	"io.MultiWriter": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func(r io.ReaderAt, off int64, n int64) *io.SectionReader
	"io.NewSectionReader": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	"(io/fs.FileMode).IsDir": SingleVarArgPropagation,
	// func ioutil.ReadAll(r io.Reader) ([]byte, error)
	"io/ioutil.ReadAll": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func ReadDir(dirname string) ([]fs.FileInfo, error)
	"io/ioutil.ReadDir": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func ioutil.ReadFile(filename string) ([]byte, error)
	"io/ioutil.ReadFile": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func WriteFile(filename string, data []byte, perm fs.FileMode) error
	"io/ioutil.WriteFile": Summary{
		[][]int{{0}, {0, 1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func NopCloser(r io.Reader) io.ReadCloser
	"io/ioutil.NopCloser": SingleVarArgPropagation,
	// func (*io.PipeWriter).Close() error
	"(*io.PipeWriter).Close": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	"(*io.PipeWriter).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
}

var summaryLog = map[string]Summarizer{
	"log.Debugf": Summary{[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
	"log.Printf": Summary{[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
	"log.Fatal":  Summary{[][]int{{}, {0, 1}}, [][]int{{}, {0}}},
	// func (l *Logger) Printf(v ...any)
	"(*log.Logger).Print": Summary{
		[][]int{{0}},
		[][]int{{}, {}, {}},
	},
	// func (l *Logger) Printf(format string, v ...any)
	"(*log.Logger).Printf": Summary{
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{}, {}, {}},
	},
	// func (l *Logger) Println(v ...any)
	"(*log.Logger).Println": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}, {}},
	},
	// func Any(key string, value any) Attr
	"log/slog.Any": TwoArgPropagation,
	// func Bool(key string, value bool) Attr
	"log/slog.Bool": TwoArgPropagation,
	// func Duration(key string, value time.Duration) Attr
	"log/slog.Duration": TwoArgPropagation,
	// func Float64(key string, value float64) Attr
	"log/slog.Float64": TwoArgPropagation,
	// func Group(key string, attrs ...Attr) Attr
	"log/slog.Group": TwoArgPropagation,
	// func Int(key string, value int) Attr
	"log/slog.Int": TwoArgPropagation,
	// func Int64(key string, value int64) Attr
	"log/slog.Int64": TwoArgPropagation,
	// func String(key string, value string) Attr
	"log/slog.String": TwoArgPropagation,
	// func Time(key string, value time.Time) Attr
	"log/slog.Time": TwoArgPropagation,
	// func Uint64(key string, value uint64) Attr
	"log/slog.Uint64": TwoArgPropagation,
	// func AnyValue(v any) Value
	"log/slog.AnyValue": SingleVarArgPropagation,
	// func BoolValue(b bool) Value
	"log/slog.BoolValue": SingleVarArgPropagation,
	// func DurationValue(d time.Duration) Value
	"log/slog.DurationValue": SingleVarArgPropagation,
	// func Float64Value(f float64) Value
	"log/slog.Float64Value": SingleVarArgPropagation,
	// func GroupValue(a ...Attr) Value
	"log/slog.GroupValue": SingleVarArgPropagation,
	// func Int64Value(i int64) Value
	"log/slog.Int64Value": SingleVarArgPropagation,
	// func IntValue(i int) Value
	"log/slog.IntValue": SingleVarArgPropagation,
	// func StringValue(s string) Value
	"log/slog.StringValue": SingleVarArgPropagation,
	// func TimeValue(t time.Time) Value
	"log/slog.TimeValue": SingleVarArgPropagation,
	// func Uint64Value(u uint64) Value
	"log/slog.Uint64Value": SingleVarArgPropagation,
}

var summaryMaps = map[string]Summarizer{
	"maps.clone": SingleVarArgPropagation,
}

var summaryMath = map[string]Summarizer{
	"math.init":                NoDataFlowPropagation,
	"math.Abs":                 SingleVarArgPropagation,
	"math.Float32bits":         SingleVarArgPropagation, // uses unsafe
	"math.Float32frombits":     SingleVarArgPropagation, // uses unsafe
	"math.Float64bits":         SingleVarArgPropagation, // uses unsafe
	"math.Float64frombits":     SingleVarArgPropagation, // uses unsafe
	"math.IsNaN":               SingleVarArgPropagation,
	"math.IsInf":               SingleVarArgPropagation,
	"math.Log2":                SingleVarArgPropagation,
	"math.Max":                 TwoArgPropagation,
	"math.Min":                 TwoArgPropagation,
	"math.Mod":                 TwoArgPropagation,
	"math.Modf":                SingleVarArgPropagation,
	"math.Pow":                 TwoArgPropagation,
	"math.Pow10":               SingleVarArgPropagation,
	"math.Round":               SingleVarArgPropagation,
	"math.RoundToEven":         SingleVarArgPropagation,
	"math/big.init":            NoDataFlowPropagation,
	"math/rand.init":           NoDataFlowPropagation,
	"math/rand.Int":            NoDataFlowPropagation,
	"math/rand.Intn":           NoDataFlowPropagation,
	"math/rand.New":            SingleVarArgPropagation,
	"math/rand.NewSource":      SingleVarArgPropagation,
	"math/rand.Seed":           NoDataFlowPropagation,
	"math/rand.Float32":        NoDataFlowPropagation,
	"math/rand/v2.init":        NoDataFlowPropagation,
	"(*math/big.Int).Mul":      TwoArgPropagation,
	"(*math/big.Int).SetInt64": TwoArgReceivePropagation,
	// func (z *big.Int) Exp(x *big.Int, y *big.Int, m *big.Int) *big.Int
	"(*math/big.Int).Exp": Summary{
		[][]int{{0}, {0, 1}, {0, 2}, {0, 3}},
		[][]int{{0}, {0}, {0}, {0}},
	},
	// func (z *big.Int) SetBytes(buf []byte) *big.Int
	"(*math/big.Int).SetBytes": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (x *big.Int) FillBytes(buf []byte) []byte
	"(*math/big.Int).FillBytes": Summary{
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

var summaryMime = map[string]Summarizer{}

var summaryNet = map[string]Summarizer{
	"net.init": NoDataFlowPropagation,
	"net.Close": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func Dial(network, address string) (Conn, error) {
	"net.Dial": Summary{
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func Listen(network, address string) (Listener, error)
	"net.Listen": Summary{
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func SplitHostPort(hostport string) (host, port string, err error)
	"net.SplitHostPort": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (l *UnixListener) Accept() (Conn, error)
	"(*net.UnixListener).Accept": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func (l *UnixListener) Close() error
	"(*net.UnixListener).Close": Summary{
		[][]int{{0}},
		[][]int{{}},
	},
	"(*net.netFD).Read": Summary{
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	"(*net.conn).Read": Summary{
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	"(*net.conn).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*net.conn).Close": Summary{
		[][]int{{0}},
		[][]int{{}},
	},
	// func (c *UnixConn) Read(b []byte) (int, error)
	"(*net.UnixConn).Read": Summary{
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	"(*net.UnixConn).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// func (l *TCPListener) Accept() (Conn, error)
	"(*net.TCPListener).Accept": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	// func (l *TCPListener) Close() error
	"(*net.TCPListener).Close": Summary{
		[][]int{{0}},
		[][]int{{}},
	},
	// func (c *TCPConn) Read(b []byte) (int, error)
	"(*net.TCPConn).Read": Summary{
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	"(*net.TCPConn).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*net.UDPConn).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*net.IPConn).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// func NewRequest(method string, url string, body io.Reader) (*Request, error)
	"net/http.NewRequest": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0, 1}, {0, 1}, {0, 1}},
	},
	"net/http.StatusText": SingleVarArgPropagation,
	// func CanonicalHeaderKey(s string) string
	"net/http.CanonicalHeaderKey": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (c *Client) Do(req *Request) (*Response, error)
	"(*net/http.Client).Do": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (h Header) Add(key string, value string)
	"(net/http.Header).Add": Summary{
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{}, {}, {}},
	},
	// func (h Header) Del(key string)
	"(net/http.Header).Del": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}, {}},
	},
	// func (h Header) Get(key string) string
	"(net/http.Header).Get": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (h Header) Set(key string, value string)
	"(net/http.Header).Set": Summary{
		[][]int{{0}, {0}, {0}},
		[][]int{{}, {}, {}},
	},
	// func (r *Request) Context() context.Context
	"(*net/http.Request).Context": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (r *Request) WithContext(ctx context.Context) *Request
	"(*net/http.Request).WithContext": Summary{
		[][]int{{0}, {1}}, // context does not taint receiver
		[][]int{{0}, {1}},
	},
	// func Parse(rawURL string) (*URL, error)
	"net/url.Parse": Summary{
		[][]int{{}},
		[][]int{{0, 1}, {0, 1}},
	},
}

var summaryOs = map[string]Summarizer{
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
	"(*os.File).Readdir": Summary{
		[][]int{{0}, {1}},
		[][]int{{0, 1}, {0, 1}},
	},
	// func (*os.File).Stat() (fs.FileInfo, error)
	"(*os.File).Stat": Summary{
		[][]int{{0}},
		[][]int{{0, 1}},
	},
	//func (*os.File).Write(b []byte) (n int, err error)
	"(*os.File).Write": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"(*os.File).WriteAt": Summary{
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{0}, {0}, {0}},
	},
	"(*os.File).WriteString": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {0}},
	},
	// func (f *File) Seek(offset int64, whence int) (ret int64, err error)
	"(*os.File).Seek": Summary{
		[][]int{{}, {0}, {0}},
		[][]int{{0}, {0}, {0}},
	},
	// func Create(name string) (*File, error)
	"os.Create": SingleVarArgPropagation,
	"os.Exit":   NoDataFlowPropagation,
	"os.Expand": Summary{
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
	"os.MkdirAll": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func Open(name string) (*File, error)
	"os.Open": SingleVarArgPropagation,
	// func OpenFile(name string, flag int, perm FileMode) (*File, error)
	"os.OpenFile": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func ReadDir(name string) ([]DirEntry, error)
	"os.ReadDir":  SingleVarArgPropagation,
	"os.ReadFile": SingleVarArgPropagation,
	// func Remove(name string) error {
	"os.Remove":           SingleVarArgPropagation,
	"os.RemoveAll":        SingleVarArgPropagation,
	"os.Rename":           Summary{[][]int{{0}, {0, 1}}, [][]int{{0}, {0}}},
	"os.Stat":             SingleVarArgPropagation,
	"(*os.fileStat).Size": SingleVarArgPropagation,
	// func (f *File) ReadAt(b []byte, off int64) (n int, err error)
	"(*os.File).ReadAt": Summary{
		[][]int{{0, 1}, {1}, {2}},
		[][]int{{0, 1}, {0, 1}, {0, 1}},
	},
}

var summaryPath = map[string]Summarizer{
	// func Join(elem ...string) string
	"path.Join":           SingleVarArgPropagation,
	"path.Base":           SingleVarArgPropagation,
	"path.Clean":          SingleVarArgPropagation,
	"path/filepath.Abs":   SingleVarArgTwoRetsPropagation,
	"path/filepath.Base":  SingleVarArgPropagation,
	"path/filepath.Clean": SingleVarArgPropagation,
	"path/filepath.Dir":   SingleVarArgPropagation,
	"path/filepath.IsAbs": SingleVarArgPropagation,
	"path/filepath.Join":  SingleVarArgPropagation,
	"path/filepath.Match": Summary{
		[][]int{{0}, {1}},
		[][]int{{0, 1}, {0, 1}},
	},
	"path/filepath.Rel": Summary{[][]int{{0}, {1}}, [][]int{{0}, {0}}},
}

var summaryPlugin = map[string]Summarizer{}

var summaryReflect = map[string]Summarizer{
	"reflect.DeepEqual": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func Indirect(v Value) Value
	"reflect.Indirect": SingleVarArgPropagation,
	// func MakeMap(typ Type) Value {
	"reflect.MakeMap": SingleVarArgPropagation,
	"reflect.MakeSlice": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	"reflect.New":     SingleVarArgPropagation,
	"reflect.TypeOf":  SingleVarArgPropagation,
	"reflect.ValueOf": SingleVarArgPropagation,
	"reflect.Zero":    SingleVarArgPropagation,
	"(reflect.Type).Kind": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (tag StructTag) Get(key string) string
	"(reflect.StructTag).Get": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(reflect.Value).Bool": SingleVarArgPropagation,
	// Over-approximation for Call: it is assumed the function being called fully propagates data
	"(reflect.Value).Call": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	"(reflect.Value).Float": SingleVarArgPropagation,
	"(reflect.Value).Int":   SingleVarArgPropagation,
	// func (v Value) Elem() Value
	"(reflect.Value).Elem": SingleVarArgPropagation,
	// func (v Value) Field(i int) Value
	"(reflect.Value).Field": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) FieldByName(name string) Value
	"(reflect.Value).FieldByName": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) FieldByIndex(index int) Value
	"(reflect.Value).FieldByIndex": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) Index(i int) Value
	"(reflect.Value).Index": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) Interface() any
	"(reflect.Value).Interface": SingleVarArgPropagation,
	// func (v Value) IsNil() bool
	"(reflect.Value).IsNil": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (v Value) IsValid() bool
	"(reflect.Value).IsValid": SingleVarArgPropagation,
	// func (v Value) Kind() Kind
	"(reflect.Value).Kind": SingleVarArgPropagation,
	// func (v Value) Len() int
	"(reflect.Value).Len": SingleVarArgPropagation,
	// func (v Value) MethodByName(name string) Value
	"(reflect.Value).MethodByName": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) NumField() int
	"(reflect.Value).NumField": SingleVarArgPropagation,
	// func (v Value) MapKeys() []Value
	"(reflect.Value).MapKeys": SingleVarArgPropagation,
	// func (v Value) MapIndex(key) []Value
	"(reflect.Value).MapIndex": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (v Value) Set(x Value)
	"(reflect.Value).Set": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}, {}},
	},
	// func (v Value) SetMapIndex(key, elem Value)
	"(reflect.Value).SetMapIndex(key, elem Value)": Summary{
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{}, {}, {}},
	},
	"(reflect.Value).String": SingleVarArgPropagation,
	// func (v Value) Type() Type
	"(reflect.Value).Type": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	//
	"(*reflect.rtype).Elem": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
}

var summaryRegexp = map[string]Summarizer{
	"regexp.Compile": SingleVarArgPropagation,
	// matching regexp doesn't taint arguments but either taints return
	"regexp.MatchString": Summary{[][]int{}, [][]int{{0}, {0}}},
	"regexp.MatchReader": Summary{[][]int{}, [][]int{{0}, {0}}},
	"regexp.MustCompile": SingleVarArgPropagation,
	"(*regexp.Regexp).Match": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (*regexp.Regexp).FindAllStringSubmatch(s string, n int) [][]string
	"(*regexp.Regexp).FindAllStringSubmatch": Summary{
		[][]int{{0}, {0}, {0}},
		[][]int{{0}, {0}, {0}},
	},
	//func (re *Regexp) FindString(s string) string
	"(*regexp.Regexp).FindString": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (re *Regexp) MatchString(s string) bool
	"(*regexp.Regexp).MatchString": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (re *Regexp) FindAllString(s string, n int) []string
	"(*regexp.Regexp).FindAllString": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func (re *Regexp) FindStringSubmatch(s string) []string
	"(*regexp.Regexp).FindStringSubmatch": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func(s string, n int) []string
	"(*regexp.Regexp).Split": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func (re *Regexp).FindAllSubmatchIndex(b []byte, n int) [][]int
	"(*regexp.Regexp).FindAllSubmatchIndex": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func (re *Regexp).FindAllStringIndex(s string, n int) [][]int
	"(*regexp.Regexp).FindAllStringIndex": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
}

var summaryRuntime = map[string]Summarizer{
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

var summarySort = map[string]Summarizer{
	// func Strings(x []string)
	"sort.Strings": Summary{
		[][]int{{0}},
		[][]int{{}},
	},
}

var summaryStrConv = map[string]Summarizer{
	"strconv.init": NoDataFlowPropagation,
	"strconv.Atoi": Summary{[][]int{{0}}, [][]int{{0}}},
	// func AppendFloat(dst []byte, f float64, fmt byte, prec, bitSize int) []byte
	"strconv.AppendFloat": Summary{
		[][]int{{0}, {0, 1}, {0, 2}, {0, 3}},
		[][]int{{0}, {0}, {0}, {0}},
	},
	"strconv.Itoa":        Summary{[][]int{{0}}, [][]int{{0}}},
	"strconv.FormatBool":  SingleVarArgPropagation,
	"strconv.FormatInt":   Summary{[][]int{{0}, {1}}, [][]int{{0}, {0}}},
	"strconv.FormatFloat": Summary{[][]int{{0}, {1}, {2}, {3}}, [][]int{{0}, {0}, {0}, {0}}},
	// func ParseBool(str string) (bool, error)
	"strconv.ParseBool": Summary{[][]int{{0}}, [][]int{{0}}},
	// func(s string, base int, bitSize int) (i int64, err error)
	"strconv.ParseInt": Summary{[][]int{{0}, {1}, {2}}, [][]int{{0}, {0}, {0}}},
	// func ParseFloat(s string, bitSize int) (float64, error)
	"strconv.ParseFloat": Summary{[][]int{{0}, {1}, {2}}, [][]int{{0}, {0}, {0}}},
	// func Quote(s string) string
	"strconv.Quote": SingleVarArgPropagation,
	// func Unquote(s string) (string, error)
	"strconv.Unquote": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
}

var summaryStrings = map[string]Summarizer{
	// func Contains(s, substr string) bool {
	"strings.Contains": Summary{
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
	"strings.Join": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {1}},
	},
	// func LastIndex(s string, substr string) int
	"strings.LastIndex": Summary{
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func NewReader(s string) *Reader
	"strings.NewReader": Summary{
		[][]int{{}},
		[][]int{{0}}, // input taints output
	},
	// func Replace(s, old, new string, n int) string {
	"strings.Replace": Summary{
		[][]int{{0}, {1}, {2}, {3}},
		[][]int{{0}, {0}, {0}, {0}},
	},
	// func ReplaceAll(s, old, new string) string {
	"strings.ReplaceAll": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func Repeat(s string, count int) string {
	"strings.Repeat": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func SplitAfterN(s string, sep string, n int) []string
	"strings.SplitAfterN": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func SplitN(s, sep string, n int) []string
	"strings.SplitN": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0}, {0}, {0}},
	},
	// func Split(s, sep string) []string
	"strings.Split": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func TrimFunc(s string, f func(rune) bool) string {
	"strings.TrimFunc": Summary{
		[][]int{{}, {}},
		[][]int{{0}, {0}},
	},
	// func TrimPrefix(s, prefix string) string {
	"strings.TrimPrefix": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func TrimRight(s, cutset string) string
	"strings.TrimRight": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func TrimSuffix(s, suffix string) string {
	"strings.TrimSuffix": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func ToLower(s string) string {
	"strings.ToLower": SingleVarArgPropagation,
	"strings.ToUpper": SingleVarArgPropagation,
	//func TrimSpace(s string) string
	"strings.TrimSpace": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (b *Builder) WriteString(s string) (int, error)
	// WriteString appends the contents of s to b's buffer.
	// It returns the length of s and a nil error.
	/* func (b *Builder) WriteString(s string) (int, error) {
		b.copyCheck()
		b.buf = append(b.buf, s...)
		return len(s), nil
	} */
	"(*strings.Builder).WriteString": Summary{
		[][]int{{0}, {1, 0}}, // input taints receiver
		[][]int{{}, {0}},     // receiver doesn't flow to results,
		//input flows only to first element of returned tuple
	},
	// func (r *Reader) Len() int
	"(*strings.Reader).Len": Summary{
		[][]int{{}},
		[][]int{{0}}, // receiver taints output
	},
	// func (r *Reader) Read(b []byte) (n int, err error)
	"(*strings.Reader).Read": Summary{
		[][]int{{1}, {}}, // receiver taints input
		[][]int{{0}, {}}, // receiver taints output
	},
	// func (r *Reader) ReadAt(b []byte, off int64) (n int, err error)
	"(*strings.Reader).ReadAt": Summary{
		[][]int{{1}, {}, {}},
		[][]int{{0}, {}, {0}},
	},
	// func (r *Reader) ReadByte() (byte, error)
	"(*strings.Reader).ReadByte": Summary{
		[][]int{{}},
		[][]int{{0}},
	},
	// func (r *Reader) ReadRune() (ch rune, size int, err error)
	"(*strings.Reader).ReadRune": Summary{
		[][]int{{}},
		[][]int{{0}},
	},
	// func (r *Reader) Seek(offset int64, whence int) (int64, error)
	"(*strings.Reader).Seek": Summary{
		[][]int{{}, {0}, {0}}, // inputs taint the receiver (state change)
		[][]int{{0}, {0}, {0}},
	},
}

var summarySync = map[string]Summarizer{
	"sync/atomic.LoadUint32": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func StoreInt32(addr *int32, val int32)
	" sync/atomic.StoreInt32": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func StoreInt64(addr *int64, val int64)
	" sync/atomic.StoreInt64": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func StoreUint32(addr *uint32, val uint32)
	"sync/atomic.StoreUint32": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func StoreUint64(addr *uint64, val uint64)
	" sync/atomic.StoreUint64": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func (v *Value) Load() (val any)
	"(*sync/atomic.Value).Load": Summary{
		[][]int{{0}},
		[][]int{{0}},
	},
	// func (v *Value) Store(val any)
	"(*sync/atomic.Value).Store": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{}},
	},
	// func (v *Value) Swap(new any) (old any)
	"(*sync/atomic.Value).Swap": Summary{
		[][]int{{0}, {0, 1}},
		[][]int{{0}, {}},
	},
	"(*sync.Map).Load":   SingleVarArgPropagation,
	"(*sync.Map).Delete": SingleVarArgPropagation,
	"(*sync.Mutex).Unlock": Summary{
		[][]int{{0}},
		[][]int{{}},
	},
	"(*sync.Mutex).Lock": Summary{
		[][]int{{0}},
		[][]int{{}},
	},
	// func (rw *RWMutex) Lock()
	"(*sync.RWMutex).Lock": NoDataFlowPropagation,
	// func (rw *RWMutex) RLock()
	"(*sync.RWMutex).RLock": NoDataFlowPropagation,
	//func (rw *RWMutex) RLocker() Locker
	"(*sync.RWMutex).RLocker": Summary{
		[][]int{{}},
		[][]int{{0}}, // receiver taints output
	},
	// func (rw *RWMutex) RUnlock()
	"(*sync.RWMutex).RUnlock": NoDataFlowPropagation,
	// func (rw *RWMutex) TryLock() bool
	"(*sync.RWMutex).TryLock": Summary{
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

var summarySyscall = map[string]Summarizer{
	"syscall.Getuid": NoDataFlowPropagation,
}

var summaryTesting = map[string]Summarizer{}

var summaryText = map[string]Summarizer{}

var summaryTime = map[string]Summarizer{
	"time.After":  SingleVarArgPropagation,
	"time.Before": SingleVarArgPropagation,
	// func Parse(layout, value string) (Time, error)
	"time.Parse": Summary{
		[][]int{{0}, {1}},
		[][]int{{0}, {0}},
	},
	// func ParseInLocation(layout string, value string, loc *Location) (Time, error
	"time.ParseInLocation": Summary{
		[][]int{{0}, {1}, {2}},
		[][]int{{0, 1}, {0, 1}, {0, 1}},
	},
	// func Sleep(d Duration)
	"time.Sleep": Summary{
		[][]int{{0}},
		[][]int{},
	},
	"time.NewTimer": SingleVarArgPropagation,
	"time.Now":      NoDataFlowPropagation,
	"time.Since":    SingleVarArgPropagation,
	// func Unix(sec int64, nsec int64) Time
	"time.Unix": Summary{
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

var summaryUnicode = map[string]Summarizer{
	"unicode.IsSpace":          SingleVarArgPropagation,
	"unicode/utf8.ValidString": SingleVarArgPropagation,
}

var summaryUnsafe = map[string]Summarizer{}

var summaryInternal = map[string]Summarizer{}

var summaryWeak = map[string]Summarizer{}
