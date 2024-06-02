package postbox

import "github.com/curtisnewbie/miso/miso"

var (
	PostboxPool *miso.AsyncPool
)

func init() {
	PostboxPool = miso.NewAsyncPool(500, 10)
}
