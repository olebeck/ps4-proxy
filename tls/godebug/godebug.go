package godebug

type Setting struct {
	name string
}

func New(name string) *Setting {
	return &Setting{name: name}
}

func (s *Setting) Value() string {
	return ""
}

func (s *Setting) IncNonDefault() {

}
