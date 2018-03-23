package i18n

import (
	"github.com/nicksnyder/go-i18n/i18n"
	"net/http"
	"path/filepath"
	"strings"
)

// 从i18n配置文件中获取id对应的翻译值.
func Get(req *http.Request, translationID string, args ...interface{}) string {
	lang := strings.Split(req.Header.Get("accept-language"), ",")
	if len(lang) == 0 {
		return translationID
	}
	T, err := i18n.Tfunc(lang[0])
	if err != nil {
		T, _ = i18n.Tfunc("zh-cn")
	}
	return T(translationID, args...)
}

// 注册i18n文件
func Register(file string) error {
	return i18n.LoadTranslationFile(file)
}

// 初始化i18n文件
func Setup(home string) {
	// register system default i18n file
	i18n.LoadTranslationFile(filepath.Join(home, "views", "i18n", "zh-cn.yaml"))
	i18n.LoadTranslationFile(filepath.Join(home, "views", "i18n", "en-us.yaml"))
}
