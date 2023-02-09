package summaries

var OtherPackages = map[string]map[string]Summary{
	"gopkg.in/yaml.v2":          SummaryYaml,
	"gopkg.in/yaml.v3":          SummaryYaml,
	"github.com/aws/aws-sdk-go": SummaryAwsSdk,
	"golang.org/x/crypto":       SummaryGolangCrypto,
}

var SummaryYaml = map[string]Summary{
	"gopkg.in/yaml.v2.yaml_parser_scan_flow_scalar":  {},
	"gopkg.in/yaml.v3.yaml_emitter_analyze_scalar":   {},
	"gopkg.in/yaml.v3.yaml_parser_scan_block_scalar": {},
}
var SummaryAwsSdk = map[string]Summary{
	"github.com/aws/aws-sdk-go/aws.mergeInConfig": {},
	// func UnmarshalXML(v interface{}, d *xml.Decoder, wrapper string) error {
	"github.com/aws/aws-sdk-go/private/protocol/xml/xmlutil.UnmarshalXML": {
		[][]int{{0}, {0, 1}, {0, 2}},
		[][]int{{0}, {0}, {0}},
	},
}

var SummaryGolangCrypto = map[string]Summary{}