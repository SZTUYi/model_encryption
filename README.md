# 模型加密（AES-GCM）

AES-256，32字节密钥，GCM，12 字节 IV

### 加密模型

./InferEngine encrypt original_files encrypted_files

可执行文件 模式 原始文件的文件夹 保存加密文件的文件夹

### 解密模型

./InferEngine decrypt encrypted_files decryp

可执行文件 模式 加密文件的文件夹 保存解密后的文件夹

### 验证

diff original_files/yolov8n_board_binary.atcnn decrypted_files/yolov8n_board_binary.atcnn_decrypted