package access

import (
	"errors"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	encoder "github.com/skip2/go-qrcode"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
)

func QR(link string) ([]byte, error) {
	if _, e := Parse(link); e != nil {
		return nil, e
	}
	return encoder.Encode(link, encoder.Medium, 384)
}
func ReadQR(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 8<<20 {
		return "", errors.New("QR image exceeds 8 MiB")
	}
	cfg, _, e := image.DecodeConfig(io.LimitReader(f, 8<<20))
	if e != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 4096 || cfg.Height > 4096 || int64(cfg.Width)*int64(cfg.Height) > 16<<20 {
		return "", errors.New("invalid QR image dimensions")
	}
	if _, e = f.Seek(0, 0); e != nil {
		return "", e
	}
	img, _, e := image.Decode(io.LimitReader(f, 8<<20))
	if e != nil {
		return "", e
	}
	bitmap, e := gozxing.NewBinaryBitmapFromImage(img)
	if e != nil {
		return "", e
	}
	result, e := qrcode.NewQRCodeReader().Decode(bitmap, map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_TRY_HARDER: true})
	if e != nil {
		return "", errors.New("CONNECT QR not found")
	}
	s := result.GetText()
	_, e = Parse(s)
	return s, e
}
