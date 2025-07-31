# Google Authenticator Exporter 架构文档

## 项目概述
Google Authenticator Exporter 是一个用于从 Google Authenticator 应用中导出 2FA（双因素认证）密钥的工具。它通过解析 Google Authenticator 生成的迁移 URI（`otpauth-migration://offline?data=...`），提取并解码其中的密钥信息，支持 JSON 输出或生成 QR 码以便导入其他密码管理器。

## 核心功能
1. **解码迁移 URI**：解析 Google Authenticator 生成的迁移 URI，提取 Base64 编码的 Protobuf 数据。
2. **Protobuf 解码**：使用 `google_auth.proto` 定义的结构解码 Protobuf 数据，提取账户信息（如密钥、名称、发行者等）。
3. **Base32 转换**：将 Base64 编码的密钥转换为 RFC3548 标准的 Base32 格式，兼容大多数 TOTP 密码管理器。
4. **输出选项**：
   - **JSON 输出**：将账户信息保存为 JSON 文件。
   - **QR 码生成**：为每个账户生成 QR 码，方便其他应用扫描导入。

## 模块设计

### 1. 主模块 (`index.js`)
- **功能**：
  - 提供命令行交互界面，提示用户输入迁移 URI。
  - 调用解码模块处理 URI，生成账户信息。
  - 根据用户选择输出 JSON 或 QR 码。
- **依赖**：
  - `protobufjs`：用于 Protobuf 解码。
  - `edbase32.js`：用于 Base32 编码。
  - `qrcode`：生成 QR 码。
  - `prompt`：命令行交互。

### 2. Protobuf 解码模块 (`google_auth.proto`)
- **功能**：
  - 定义了 Google Authenticator 迁移数据的 Protobuf 结构。
  - 包含账户信息的字段（如密钥、算法、发行者等）。

### 3. Base32 编码模块 (`edbase32.js`)
- **功能**：
  - 将二进制数据转换为 RFC3548 标准的 Base32 字符串。
  - 用于生成兼容 TOTP 密码管理器的密钥格式。

### 4. 测试模块 (`index.test.js`)
- **功能**：
  - 提供单元测试，验证核心功能的正确性。

## 数据流
1. **输入**：用户通过命令行输入迁移 URI。
2. **解码**：
   - URI 解码为 Base64 数据。
   - Base64 数据解码为 Protobuf 二进制。
   - Protobuf 解码为账户信息。
3. **转换**：将密钥从 Base64 转换为 Base32。
4. **输出**：根据用户选择生成 JSON 或 QR 码。

## 依赖项
- **运行时依赖**：
  - `protobufjs`：Protobuf 解码。
  - `qrcode`：QR 码生成。
  - `prompt`：命令行交互。
- **开发依赖**：
  - `vitest`：单元测试框架。

## 使用场景
1. **迁移到其他密码管理器**：将 Google Authenticator 的 2FA 密钥导出为 JSON 或 QR 码，方便导入其他工具（如 Authy、Aegis 等）。
2. **备份密钥**：将密钥保存为 JSON 文件，避免丢失手机时无法访问 2FA 账户。

## 限制
- **安全性**：迁移 URI 包含敏感信息，需确保传输和存储安全。
- **兼容性**：仅支持 Google Authenticator 生成的迁移 URI。

## 后续改进
1. **支持更多输入方式**：如直接扫描 QR 码图片。
2. **增强安全性**：支持加密存储 JSON 文件。
3. **扩展兼容性**：支持其他 2FA 应用的迁移格式。