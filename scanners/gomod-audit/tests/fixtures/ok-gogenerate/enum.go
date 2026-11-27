package enum

//go:generate stringer -type=Kind
//go:generate sh -c "protoc --go_out=. *.proto && gofmt -w ."

// Kind is an enum.
type Kind int
