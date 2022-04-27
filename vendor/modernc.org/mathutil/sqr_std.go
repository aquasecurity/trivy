// +build riscv64

package mathutil

func (f *float) sqr() {
	f.n.Mul(f.n, f.n)
	f.fracBits *= 2
	f.normalize()
}
