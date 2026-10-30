# Haoxue Download
基于好学App的课程回放下载路线，支持按课程名和按日期查找回放。

## 环境要求

- Python 3.10 或更高版本
- `ffmpeg`，用于解析 m3u8 并转换为 mp4；需要安装到系统并加入 `PATH`

新发布的回放可能只提供 MP4 直链，此时无需 `ffmpeg`，下载会自动使用 HTTP Range 断点续传。

## 运行

### 使用 uv

项目使用 `pyproject.toml` 声明依赖，并使用 `uv.lock` 锁定版本。安装 [uv](https://docs.astral.sh/uv/) 后，在项目目录执行：

```sh
# 创建或同步项目虚拟环境并安装锁定依赖
uv sync

# 在项目环境中运行
uv run haoxue_download.py
```

更新依赖时修改 `pyproject.toml`，然后执行 `uv lock` 更新锁文件；提交代码时一并提交 `pyproject.toml` 和 `uv.lock`。

### 使用裸 Python

也可以不使用 uv，直接用任意 Python 3.10+ 环境安装依赖：

```sh
python -m pip install requests pycryptodome
python haoxue_download.py
```

然后填写学号、密码，选择课程或日期并下载回放。

如果已经通过 uv 创建了环境，也可以直接调用其中的 Python：

```sh
.venv/Scripts/python.exe haoxue_download.py
```

## 使用方法

程序启动后会要求输入账号和密码，然后可输入 `1/2` 选择两种查找方式：

1. 按课程查找：输入课程搜索条件，再选择课程和节次；仍会自动扫描课程内被隐藏的回放。
2. 按日期查找：输入 `YYYY-MM-DD`，或 `START..END` 查询一段日期（最长 31 天），再选择课程记录；直接回车时默认查询昨天。结果会用 `[hidden-course]` 标出课程搜索里找不到的课程，状态不是“回放可用”的记录也会尝试解析一次媒体地址。

调试 HTTP、API 和 ffmpeg 信息时可以添加 `--verbose`：

```sh
# 使用 Python
python haoxue_download.py --verbose

# 使用 uv
uv run ./haoxue_download.py --verbose
```
