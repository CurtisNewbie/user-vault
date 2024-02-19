package vault

import "github.com/curtisnewbie/miso/miso"

var (
	monitorPool = miso.NewAsyncPool(500, 10)
	commonPool  = miso.NewAsyncPool(500, 10)
)
