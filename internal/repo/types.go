package repo

type Identifier struct {
	Owner string
	Name  string
}

func (r Identifier) FullName() string {
	return r.Owner + "/" + r.Name
}
