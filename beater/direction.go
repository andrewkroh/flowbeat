package beater

type FlowDirection uint8

const (
	Ingress FlowDirection = iota
	Egress
)

var flowDirectionNames = map[FlowDirection]string{
	Ingress: "ingress",
	Egress:  "egress",
}

func (d FlowDirection) String() string {
	name, found := flowDirectionNames[d]
	if found {
		return name
	}
	return "unknown"
}
