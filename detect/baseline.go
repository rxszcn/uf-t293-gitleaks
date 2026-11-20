package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
)

func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintenance if/when the Finding struct changes
	for _, b := range baseline {
		if finding.RuleID == b.RuleID &&
			finding.Description == b.Description &&
			finding.StartLine == b.StartLine &&
			finding.EndLine == b.EndLine &&
			finding.StartColumn == b.StartColumn &&
			finding.EndColumn == b.EndColumn &&
			(redact > 0 || (finding.Match == b.Match && finding.Secret == b.Secret)) &&
			finding.File == b.File &&
			finding.Commit == b.Commit &&
			finding.Author == b.Author &&
			finding.Email == b.Email &&
			finding.Date == b.Date &&
			finding.Message == b.Message &&
			// Omit checking finding.Fingerprint - if the format of the fingerprint changes, the users will see unexpected behaviour
			finding.Entropy == b.Entropy {
			return false
		}
	}
	return true
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	var previousFindings []report.Finding
	err = json.Unmarshal(bytes, &previousFindings)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}
	if previousFindings == nil {
		// 内容为 null 等无法产生有效基线的情况（例如旧版本格式），
		// 显式报错，不允许静默降级为无基线
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return previousFindings, nil
}

func (d *Detector) AddBaseline(baselinePath string, source string) error {
	if baselinePath == "" {
		d.baselinePath = baselinePath
		return nil
	}

	absoluteSource, err := filepath.Abs(source)
	if err != nil {
		return err
	}

	absoluteBaseline, err := filepath.Abs(baselinePath)
	if err != nil {
		return err
	}

	relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
	if err != nil {
		// 基线位于扫描源之外（例如不同盘符）时无法计算源内相对形态；
		// 此时基线文件不可能进入扫描面，仅保留绝对形态即可，不视为加载失败
		logging.Debug().Err(err).Msg("baseline path is outside the scan source, using absolute form only")
		relativeBaseline = ""
	}

	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		return err
	}

	// 记录扫描源的绝对形态，基线比对时据此把绝对路径形态的
	// finding 归一到源内相对形态，使比对结果与调用源形态无关
	d.baselineSource = absoluteSource
	// 基线登记的 File 在装载时统一归一到源内相对形态，
	// 保证登记内容与扫描内容在比对时刻同形态呈现
	for i := range baseline {
		baseline[i].File = relPathToSource(absoluteSource, baseline[i].File)
	}
	d.baseline = baseline
	// 基线报告自身的路径同时保留源内相对形态与绝对形态，
	// 用于把基线文件排除在扫描面之外
	d.baselinePath = normalizePath(relativeBaseline)
	d.baselineAbsPath = normalizePath(absoluteBaseline)
	return nil
}

// normalizePath 把路径归一为 Clean + 斜杠分隔的形态，
// 消除 Windows 反斜杠、"./" 前缀等形态差异
func normalizePath(p string) string {
	if p == "" {
		return p
	}
	return filepath.ToSlash(filepath.Clean(p))
}

// relPathToSource 把路径归一到扫描源内的相对形态：
// 绝对路径转换为相对 source 的路径，相对路径仅做形态归一
func relPathToSource(absoluteSource, p string) string {
	if p == "" || absoluteSource == "" {
		return normalizePath(p)
	}
	if filepath.IsAbs(p) {
		if rel, err := filepath.Rel(absoluteSource, p); err == nil {
			return normalizePath(rel)
		}
	}
	return normalizePath(p)
}

// isBaselinePath 判断 fragment 路径是否指向基线报告文件自身，
// 判定与调用源形态（相对/绝对）及路径分隔符形态无关
func (d *Detector) isBaselinePath(path string) bool {
	if d.baselinePath == "" && d.baselineAbsPath == "" {
		return false
	}
	// 源内相对形态比较，覆盖相对路径调用源（含基线位于嵌套子目录的情况）
	if d.baselinePath != "" && (path == d.baselinePath || normalizePath(path) == d.baselinePath) {
		return true
	}
	// 绝对形态比较，覆盖绝对路径调用源
	if d.baselineAbsPath != "" {
		if normalizePath(path) == d.baselineAbsPath {
			return true
		}
		if abs, err := filepath.Abs(path); err == nil && normalizePath(abs) == d.baselineAbsPath {
			return true
		}
	}
	return false
}
