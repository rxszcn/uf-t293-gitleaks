package detect

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func TestIsNew(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		findings report.Finding
		redact   uint
		baseline []report.Finding
		expect   bool
	}{
		// new
		"new - commit doesn't match baseline": {
			findings: report.Finding{
				Commit: "0000",
				Author: "a",
			},
			baseline: []report.Finding{
				{
					Commit: "0002",
					Author: "a",
				},
			},
			expect: true,
		},
		"new - redacted, different baseline": {
			findings: report.Finding{
				RuleID:      "private-key",
				Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
				StartLine:   1,
				EndLine:     15,
				StartColumn: 1,
				EndColumn:   30,
				Match:       "REDACTED",
				Secret:      "REDACTED",
				File:        "key.txt",
				Commit:      "6d3ba1f7653822c0f8ac9a9af56daaa2cd8bbcad",
				Entropy:     5.9834013,
				Author:      "James Bond",
				Email:       "jbond@gov.co.uk",
				Date:        "2025-03-02T15:10:40Z",
				Message:     "init",
				Fingerprint: "6d3ba1f7653822c0f8ac9a9af56daaa2cd8bbcad:key.txt:private-key:1",
			},
			baseline: []report.Finding{
				{
					RuleID:      "private-key",
					Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
					StartLine:   1,
					EndLine:     15,
					StartColumn: 1,
					EndColumn:   30,
					Match:       "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgFIckgeuo80H6skLd1FKYfJC75/tnmtDWO4Rf2AFqrYZdu71VKGR\noGfEVl7AmvxTd9u6tnPtWjAeu9k2VMQcOtXEwgU0A6H09EBcS1EVN/I8pcNw1qjO\nkJ7ZA8AhZk/OpVAK7665CEny7ISRNZnx1nPaHjlb8lebPzlWOvxX9wjbAgMBAAEC\ngYBN6wqv+4s4juC/cwAAxeL4L4iQbL497yS+lSAYEIiUUMnJrEhpIXXjwi5rr73i\n35oHisCEdaF1tFRxpNr/VgKFsM1KqQUZvCVRE9Rokfe23QkQDvcxh9CI/Ah9Eofp\nx/m5DjSsRKrbIpOOAC3J3B/s02HRmxy8tRYnQVqWXzAH8QJBAJdBgXi62KI1eytU\n7l3Q8ymkS1OHzSOGBEYPpZZQ7WRpZlv/06cKfJBT/dGgA4z9i9ySs8cWUoh+FGYX\nlkDB4c0CQQCK+TwfAFvrkSWorZ9Gjb6y2LZQPUufTzJNhzhK5XObCDbwyMXEM/Vs\newiyUFljlI/A9PjcrmkgrDLUMD4+og1HAkAs2t01W1uhBvEm0YH6yltCDxnThKM+\nFKEx0bQOVqN/so4LXFt83uw/tNjBkI1dA1e1qr+rm6AQICuWdwo03ApFAkBktes4\nuCTk2GHHFFM5aN0KdHviOBlGULkub9B+jjsx3UkbQxP2dITlYV/TAOFWhcGLXru+\nCPKMR93p4TAqaXtfAkA+ZZDb0mA9rtaetJlSoo6XgwI/+kqltADch9dcyqYBHwjr\nAEkzUKvmCxNAK4GEPA79FZFp30kDx+buysyeX9qY\n-----END RSA PRIVATE KEY-----",
					Secret:      "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgFIckgeuo80H6skLd1FKYfJC75/tnmtDWO4Rf2AFqrYZdu71VKGR\noGfEVl7AmvxTd9u6tnPtWjAeu9k2VMQcOtXEwgU0A6H09EBcS1EVN/I8pcNw1qjO\nkJ7ZA8AhZk/OpVAK7665CEny7ISRNZnx1nPaHjlb8lebPzlWOvxX9wjbAgMBAAEC\ngYBN6wqv+4s4juC/cwAAxeL4L4iQbL497yS+lSAYEIiUUMnJrEhpIXXjwi5rr73i\n35oHisCEdaF1tFRxpNr/VgKFsM1KqQUZvCVRE9Rokfe23QkQDvcxh9CI/Ah9Eofp\nx/m5DjSsRKrbIpOOAC3J3B/s02HRmxy8tRYnQVqWXzAH8QJBAJdBgXi62KI1eytU\n7l3Q8ymkS1OHzSOGBEYPpZZQ7WRpZlv/06cKfJBT/dGgA4z9i9ySs8cWUoh+FGYX\nlkDB4c0CQQCK+TwfAFvrkSWorZ9Gjb6y2LZQPUufTzJNhzhK5XObCDbwyMXEM/Vs\newiyUFljlI/A9PjcrmkgrDLUMD4+og1HAkAs2t01W1uhBvEm0YH6yltCDxnThKM+\nFKEx0bQOVqN/so4LXFt83uw/tNjBkI1dA1e1qr+rm6AQICuWdwo03ApFAkBktes4\nuCTk2GHHFFM5aN0KdHviOBlGULkub9B+jjsx3UkbQxP2dITlYV/TAOFWhcGLXru+\nCPKMR93p4TAqaXtfAkA+ZZDb0mA9rtaetJlSoo6XgwI/+kqltADch9dcyqYBHwjr\nAEkzUKvmCxNAK4GEPA79FZFp30kDx+buysyeX9qY\n-----END RSA PRIVATE KEY-----",
					File:        "key.txt",
					Commit:      "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4",
					Entropy:     5.9834013,
					Author:      "James Bond",
					Email:       "jbond@gov.co.uk",
					Date:        "2025-02-02T17:45:30Z",
					Message:     "init",
					Fingerprint: "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4:key.txt:private-key:1",
				},
			},
			expect: true,
		},

		// not new
		"not new - commit+author matches": {
			findings: report.Finding{
				Commit: "0000",
				Author: "a",
			},
			baseline: []report.Finding{
				{
					Commit: "0000",
					Author: "a",
				},
			},
			expect: false,
		},
		"not new - commit+author matches, tags ignored": {
			findings: report.Finding{
				Commit: "0000",
				Author: "a",
				Tags:   []string{"a", "b"},
			},
			baseline: []report.Finding{
				{
					Commit: "0000",
					Author: "a",
					Tags:   []string{"a", "c"},
				},
			},
			expect: false, // Updated tags doesn't make it a new finding
		},
		"not new - redacted, everything else matches": {
			findings: report.Finding{
				RuleID:      "private-key",
				Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
				StartLine:   1,
				EndLine:     15,
				StartColumn: 1,
				EndColumn:   30,
				Match:       "REDACTED",
				Secret:      "REDACTED",
				File:        "key.txt",
				Commit:      "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4",
				Entropy:     5.9834013,
				Author:      "James Bond",
				Email:       "jbond@gov.co.uk",
				Date:        "2025-02-02T17:45:30Z",
				Message:     "init",
				Fingerprint: "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4:key.txt:private-key:1",
			},
			redact: 100,
			baseline: []report.Finding{
				{
					RuleID:      "private-key",
					Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
					StartLine:   1,
					EndLine:     15,
					StartColumn: 1,
					EndColumn:   30,
					Match:       "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgFIckgeuo80H6skLd1FKYfJC75/tnmtDWO4Rf2AFqrYZdu71VKGR\noGfEVl7AmvxTd9u6tnPtWjAeu9k2VMQcOtXEwgU0A6H09EBcS1EVN/I8pcNw1qjO\nkJ7ZA8AhZk/OpVAK7665CEny7ISRNZnx1nPaHjlb8lebPzlWOvxX9wjbAgMBAAEC\ngYBN6wqv+4s4juC/cwAAxeL4L4iQbL497yS+lSAYEIiUUMnJrEhpIXXjwi5rr73i\n35oHisCEdaF1tFRxpNr/VgKFsM1KqQUZvCVRE9Rokfe23QkQDvcxh9CI/Ah9Eofp\nx/m5DjSsRKrbIpOOAC3J3B/s02HRmxy8tRYnQVqWXzAH8QJBAJdBgXi62KI1eytU\n7l3Q8ymkS1OHzSOGBEYPpZZQ7WRpZlv/06cKfJBT/dGgA4z9i9ySs8cWUoh+FGYX\nlkDB4c0CQQCK+TwfAFvrkSWorZ9Gjb6y2LZQPUufTzJNhzhK5XObCDbwyMXEM/Vs\newiyUFljlI/A9PjcrmkgrDLUMD4+og1HAkAs2t01W1uhBvEm0YH6yltCDxnThKM+\nFKEx0bQOVqN/so4LXFt83uw/tNjBkI1dA1e1qr+rm6AQICuWdwo03ApFAkBktes4\nuCTk2GHHFFM5aN0KdHviOBlGULkub9B+jjsx3UkbQxP2dITlYV/TAOFWhcGLXru+\nCPKMR93p4TAqaXtfAkA+ZZDb0mA9rtaetJlSoo6XgwI/+kqltADch9dcyqYBHwjr\nAEkzUKvmCxNAK4GEPA79FZFp30kDx+buysyeX9qY\n-----END RSA PRIVATE KEY-----",
					Secret:      "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgFIckgeuo80H6skLd1FKYfJC75/tnmtDWO4Rf2AFqrYZdu71VKGR\noGfEVl7AmvxTd9u6tnPtWjAeu9k2VMQcOtXEwgU0A6H09EBcS1EVN/I8pcNw1qjO\nkJ7ZA8AhZk/OpVAK7665CEny7ISRNZnx1nPaHjlb8lebPzlWOvxX9wjbAgMBAAEC\ngYBN6wqv+4s4juC/cwAAxeL4L4iQbL497yS+lSAYEIiUUMnJrEhpIXXjwi5rr73i\n35oHisCEdaF1tFRxpNr/VgKFsM1KqQUZvCVRE9Rokfe23QkQDvcxh9CI/Ah9Eofp\nx/m5DjSsRKrbIpOOAC3J3B/s02HRmxy8tRYnQVqWXzAH8QJBAJdBgXi62KI1eytU\n7l3Q8ymkS1OHzSOGBEYPpZZQ7WRpZlv/06cKfJBT/dGgA4z9i9ySs8cWUoh+FGYX\nlkDB4c0CQQCK+TwfAFvrkSWorZ9Gjb6y2LZQPUufTzJNhzhK5XObCDbwyMXEM/Vs\newiyUFljlI/A9PjcrmkgrDLUMD4+og1HAkAs2t01W1uhBvEm0YH6yltCDxnThKM+\nFKEx0bQOVqN/so4LXFt83uw/tNjBkI1dA1e1qr+rm6AQICuWdwo03ApFAkBktes4\nuCTk2GHHFFM5aN0KdHviOBlGULkub9B+jjsx3UkbQxP2dITlYV/TAOFWhcGLXru+\nCPKMR93p4TAqaXtfAkA+ZZDb0mA9rtaetJlSoo6XgwI/+kqltADch9dcyqYBHwjr\nAEkzUKvmCxNAK4GEPA79FZFp30kDx+buysyeX9qY\n-----END RSA PRIVATE KEY-----",
					File:        "key.txt",
					Commit:      "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4",
					Entropy:     5.9834013,
					Author:      "James Bond",
					Email:       "jbond@gov.co.uk",
					Date:        "2025-02-02T17:45:30Z",
					Message:     "init",
					Fingerprint: "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4:key.txt:private-key:1",
				},
			},
			expect: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expect, IsNew(test.findings, test.redact, test.baseline))
		})
	}
}

func TestFileLoadBaseline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Filename      string
		ExpectedError error
	}{
		{
			Filename:      "../testdata/baseline/baseline.csv",
			ExpectedError: errors.New("the format of the file ../testdata/baseline/baseline.csv is not supported"),
		},
		{
			Filename:      "../testdata/baseline/baseline.sarif",
			ExpectedError: errors.New("the format of the file ../testdata/baseline/baseline.sarif is not supported"),
		},
		{
			Filename:      "../testdata/baseline/notfound.json",
			ExpectedError: errors.New("could not open ../testdata/baseline/notfound.json"),
		},
	}

	for _, test := range tests {
		_, err := LoadBaseline(test.Filename)
		assert.Equal(t, test.ExpectedError, err)
	}
}

func TestIgnoreIssuesInBaseline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		findings    []report.Finding
		baseline    []report.Finding
		expectCount int
	}{
		{
			findings: []report.Finding{
				{
					Author: "a",
					Commit: "5",
				},
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "5",
				},
			},
			expectCount: 0,
		},
		{
			findings: []report.Finding{
				{
					Author:      "a",
					Commit:      "5",
					Fingerprint: "a",
				},
			},
			baseline: []report.Finding{
				{
					Author:      "a",
					Commit:      "5",
					Fingerprint: "b",
				},
			},
			expectCount: 0,
		},
	}

	for _, test := range tests {
		d, err := NewDetectorDefaultConfig()
		require.NoError(t, err)
		d.baseline = test.baseline
		for _, finding := range test.findings {
			d.AddFinding(finding)
		}
		assert.Len(t, d.findings, test.expectCount)
	}
}

// baselineMatrixSecret 命中默认配置 generic-api-key 规则（entropy 3.5）的测试密钥
const baselineMatrixSecret = `const api_key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`

// TestBaselineSourceAndLocationMatrix 覆盖基线机制的输入矩阵：
// {相对源, 绝对源} x {根级基线, 子目录基线} 固定四组。
// 验证两种调用形态与两种基线存放位置下基线均生效（基线登记的历史泄露被剔除），
// 且基线报告文件自身不进入扫描面（基线内登记的历史密钥不被二次报成新泄露）。
//
// 注意：本测试通过 t.Chdir 构造相对路径调用形态，不能标记为 parallel。
func TestBaselineSourceAndLocationMatrix(t *testing.T) {
	tests := map[string]struct {
		absoluteSource bool
		baselineSubDir bool
	}{
		"相对源 + 根级基线":   {absoluteSource: false, baselineSubDir: false},
		"相对源 + 子目录基线":  {absoluteSource: false, baselineSubDir: true},
		"绝对源 + 根级基线":   {absoluteSource: true, baselineSubDir: false},
		"绝对源 + 子目录基线": {absoluteSource: true, baselineSubDir: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "key.txt"), []byte(baselineMatrixSecret), 0o644))

			// 本地开发者形态：在仓库目录内以相对路径发起全量扫描建档，
			// 基线登记的 File 为相对形态
			t.Chdir(tmpDir)
			baselineRelPath := "baseline.json"
			if tt.baselineSubDir {
				require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "reports"), 0o755))
				baselineRelPath = filepath.Join("reports", "baseline.json")
			}

			createDetector, err := NewDetectorDefaultConfig()
			require.NoError(t, err)
			baselineFindings, err := createDetector.DetectSource(context.Background(), &sources.Files{
				Config: &createDetector.Config,
				Path:   ".",
				Sema:   createDetector.Sema,
			})
			require.NoError(t, err)
			require.NotEmpty(t, baselineFindings, "全量扫描应检出测试密钥，否则基线为空无法验证增量放行")

			data, err := json.Marshal(baselineFindings)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, baselineRelPath), data, 0o644))

			// 按矩阵指定的调用形态与基线位置发起增量扫描
			source := "."
			baselinePath := baselineRelPath
			if tt.absoluteSource {
				source = tmpDir
				baselinePath = filepath.Join(tmpDir, baselineRelPath)
			}

			d, err := NewDetectorDefaultConfig()
			require.NoError(t, err)
			require.NoError(t, d.AddBaseline(baselinePath, source))

			findings, err := d.DetectSource(context.Background(), &sources.Files{
				Config: &d.Config,
				Path:   source,
				Sema:   d.Sema,
			})
			require.NoError(t, err)
			assert.Empty(t, findings, "基线登记的历史泄露应被剔除，且基线报告自身不应进入扫描面")
		})
	}
}

// TestAddBaselineLoadFailure 覆盖基线加载失败形态：
// 基线文件缺失、内容损坏、内容无效（如旧版本格式产生的 null）时，
// AddBaseline 必须显式返回错误且不装配任何基线，
// 由命令装配入口决定显式失败，不再静默降级为无基线全量扫描。
func TestAddBaselineLoadFailure(t *testing.T) {
	tmpDir := t.TempDir()

	corruptPath := filepath.Join(tmpDir, "corrupt.json")
	require.NoError(t, os.WriteFile(corruptPath, []byte("{not-json"), 0o644))

	nullPath := filepath.Join(tmpDir, "null.json")
	require.NoError(t, os.WriteFile(nullPath, []byte("null"), 0o644))

	tests := map[string]struct {
		baselinePath string
	}{
		"基线文件缺失":      {baselinePath: filepath.Join(tmpDir, "missing.json")},
		"基线内容损坏":      {baselinePath: corruptPath},
		"基线内容无效(null)": {baselinePath: nullPath},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, err := NewDetectorDefaultConfig()
			require.NoError(t, err)
			err = d.AddBaseline(tt.baselinePath, tmpDir)
			require.Error(t, err, "基线加载失败必须显式返回错误")
			assert.Nil(t, d.baseline, "加载失败时不应装配任何基线")
		})
	}
}
