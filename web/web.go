// Package web 内嵌前端静态文件，供 panel 提供 UI。
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:files
var files embed.FS

// UI 前端文件系统（files/ 目录挂到根路径）。
var UI, _ = fs.Sub(files, "files")
