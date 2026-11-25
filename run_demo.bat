@echo off
REM ============================================================
REM quarprom 原生 Windows 一键演示（仅依赖 Python 3.12 标准库）
REM 用法： run_demo.bat
REM ============================================================
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] 未在 PATH 中找到 python，请先安装 Python 3.12。
    exit /b 90
)

python --version
REM 默认物理基准 6000 条（秒级）、清单基准满 6 万条；加 --full-physical 可跑满 6 万物理文件
python run_demo.py %*
set RC=%ERRORLEVEL%

echo.
echo 运行单元测试...
python -m unittest discover -s tests -v
set TEST_RC=%ERRORLEVEL%

if %RC% NEQ 0 (
    echo [FAIL] 端到端演示失败，退出码 %RC%
    exit /b %RC%
)
if %TEST_RC% NEQ 0 (
    echo [FAIL] 单元测试失败，退出码 %TEST_RC%
    exit /b %TEST_RC%
)
echo [OK] 演示与单元测试全部通过。
endlocal
