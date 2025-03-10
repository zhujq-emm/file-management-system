<template>
  <div class="app-container">
    <!-- 已登录状态 -->
    <el-container v-if="isLoggedIn">
      <el-header>
        <div class="header-content">
          <h1>奇奇文件管理系统</h1>
          <div class="user-info">
            <span class="username">当前用户：{{ currentUser }}</span>
            <el-button type="danger" size="small" @click="logout">退出登录</el-button>
          </div>
        </div>
      </el-header>
      
      <el-main>
        <!-- 管理员控制区域 -->
        <div v-if="isAdmin" class="admin-controls">
          <el-button type="primary" @click="showRegisterDialog">注册新用户</el-button>
          <el-button type="success" @click="showCategoryDialog">添加分类</el-button>
          
          <!-- 文件上传区域 -->
          <el-upload
            class="upload-demo"
            ref="uploadRef"
            :action="uploadUrl"
            :headers="uploadHeaders"
            :data="uploadData"
            :on-success="handleUploadSuccess"
            :on-error="handleUploadError"
            :before-upload="beforeUpload"
            :auto-upload="false"
            :show-file-list="true"
          >
            <template #trigger>
              <el-button type="primary">选择文件</el-button>
            </template>
            
            <el-button class="ml-3" type="success" @click="submitUpload">
              开始上传
            </el-button>
            
            <template #tip>
              <div class="el-upload__tip">
                <el-select v-model="selectedCategory" placeholder="请选择文件分类">
                  <el-option
                    v-for="category in categories"
                    :key="category.id"
                    :label="category.name"
                    :value="category.id"
                  />
                </el-select>
              </div>
            </template>
          </el-upload>
        </div>

        <!-- 分类过滤器 -->
        <div class="category-filter">
          <el-radio-group v-model="currentCategory" @change="filterFiles">
            <el-radio-button value="all">全部文件</el-radio-button>
            <el-radio-button 
              v-for="category in categories" 
              :key="category.id" 
              :label="category.id"
            >
              {{ category.name }}
            </el-radio-button>
          </el-radio-group>
        </div>
        
        <!-- 文件列表 -->
        <el-table 
          :data="filteredFiles" 
          style="width: 100%"
          v-loading="tableLoading"
        >
          <el-table-column prop="name" label="文件名" min-width="200">
            <template #default="scope">
              <el-tooltip 
                :content="scope.row.originalName || scope.row.name" 
                placement="top"
              >
                <span>{{ scope.row.originalName || scope.row.name }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          
          <el-table-column prop="uploadedBy" label="上传者" width="120"></el-table-column>
          
          <el-table-column prop="category" label="分类" width="120">
            <template #default="scope">
              {{ getCategoryName(scope.row.category) }}
            </template>
          </el-table-column>
          
          <el-table-column prop="uploadDate" label="上传时间" width="180">
            <template #default="scope">
              {{ formatDate(scope.row.uploadDate) }}
            </template>
          </el-table-column>
          
          <el-table-column prop="size" label="大小" width="120">
            <template #default="scope">
              {{ formatFileSize(scope.row.size) }}
            </template>
          </el-table-column>
          
          <el-table-column label="操作" width="200" fixed="right">
            <template #default="scope">
              <el-button 
                type="primary" 
                size="small" 
                @click="downloadFile(scope.row)"
              >下载</el-button>
              <el-button 
                v-if="isAdmin" 
                type="danger"
                size="small"
                @click="deleteFile(scope.row)"
              >删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-main>
    </el-container>
    
    <!-- 登录表单 -->
    <div v-else class="login-container">
      <el-form 
        :model="loginForm" 
        label-width="80px"
        @keyup.enter="login"
      >
        <h2 class="login-title">文件管理系统</h2>
        <el-form-item label="用户名">
          <el-input v-model="loginForm.username"></el-input>
        </el-form-item>
        <el-form-item label="密码">
          <el-input 
            v-model="loginForm.password" 
            type="password"
            show-password
          ></el-input>
        </el-form-item>
        <el-form-item>
          <el-button 
            type="primary" 
            @click="login"
            :loading="loginLoading"
          >登录</el-button>
        </el-form-item>
      </el-form>
    </div>
    
    <!-- 注册对话框 -->
    <el-dialog 
      v-model="registerDialogVisible" 
      title="注册新用户"
      width="400px"
      destroy-on-close
    >
      <el-form 
        ref="registerFormRef"
        :model="registerForm" 
        :rules="registerRules"
        label-width="80px"
      >
        <el-form-item label="用户名" prop="username">
          <el-input v-model="registerForm.username"></el-input>
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input 
            v-model="registerForm.password" 
            type="password"
            show-password
          ></el-input>
        </el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="registerForm.role" placeholder="请选择角色">
            <el-option label="普通用户" value="user"></el-option>
            <el-option label="管理员" value="admin"></el-option>
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="closeRegisterDialog">取消</el-button>
        <el-button 
          type="primary" 
          @click="register"
          :loading="registerLoading"
        >确定</el-button>
      </template>
    </el-dialog>

    <!-- 添加分类对话框 -->
    <el-dialog 
      v-model="categoryDialogVisible" 
      title="添加新分类"
      width="400px"
      destroy-on-close
    >
      <el-form 
        ref="categoryFormRef"
        :model="categoryForm" 
        :rules="categoryRules"
        label-width="80px"
      >
        <el-form-item label="分类名称" prop="name">
          <el-input v-model="categoryForm.name"></el-input>
        </el-form-item>
        <el-form-item label="分类描述" prop="description">
          <el-input 
            type="textarea" 
            v-model="categoryForm.description"
            :rows="3"
          ></el-input>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="closeCategoryDialog">取消</el-button>
        <el-button 
          type="primary" 
          @click="createCategory"
          :loading="categoryLoading"
        >确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:3000/api';
const isLoggedIn = ref(false);
const isAdmin = ref(false);
const currentUser = ref('');
const files = ref([]);
const uploadRef = ref(null);
const registerFormRef = ref(null);
const categoryFormRef = ref(null);

// 加载状态
const loginLoading = ref(false);
const registerLoading = ref(false);
const categoryLoading = ref(false);
const tableLoading = ref(false);

// 表单数据
const loginForm = ref({ username: '', password: '' });
const registerForm = ref({ username: '', password: '', role: 'user' });
const categoryForm = ref({ name: '', description: '' });

// 对话框控制
const registerDialogVisible = ref(false);
const categoryDialogVisible = ref(false);

// 文件分类相关
const categories = ref([]);
const selectedCategory = ref('default');
const currentCategory = ref('all');

// 表单验证规则
const registerRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 3, max: 20, message: '长度在 3 到 20 个字符', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, max: 20, message: '长度在 6 到 20 个字符', trigger: 'blur' }
  ],
  role: [
    { required: true, message: '请选择角色', trigger: 'change' }
  ]
};

const categoryRules = {
  name: [
    { required: true, message: '请输入分类名称', trigger: 'blur' },
    { min: 2, max: 20, message: '长度在 2 到 20 个字符', trigger: 'blur' }
  ],
  description: [
    { required: true, message: '请输入分类描述', trigger: 'blur' },
    { max: 100, message: '最多 100 个字符', trigger: 'blur' }
  ]
};

// 计算属性
const uploadHeaders = computed(() => ({
  Authorization: `Bearer ${localStorage.getItem('token')}`
}));

const uploadData = computed(() => ({
  category: selectedCategory.value
}));

const uploadUrl = `${API_BASE_URL}/upload`;

const filteredFiles = computed(() => {
  if (currentCategory.value === 'all') {
    return files.value;
  }
  return files.value.filter(file => file.category === currentCategory.value);
});

// 生命周期钩子
onMounted(async () => {
  const token = localStorage.getItem('token');
  if (token) {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      currentUser.value = payload.username;
      isAdmin.value = payload.role === 'admin';
      isLoggedIn.value = true;
      await Promise.all([fetchFiles(), fetchCategories()]);
    } catch (error) {
      localStorage.removeItem('token');
      isLoggedIn.value = false;
    }
  }
});

// 方法定义
// 登录相关
const login = async () => {
  if (!loginForm.value.username || !loginForm.value.password) {
    ElMessage.warning('请输入用户名和密码');
    return;
  }

  loginLoading.value = true;
  try {
    const response = await axios.post(`${API_BASE_URL}/login`, loginForm.value);
    localStorage.setItem('token', response.data.token);
    isAdmin.value = response.data.role === 'admin';
    isLoggedIn.value = true;
    currentUser.value = loginForm.value.username;
    await Promise.all([fetchFiles(), fetchCategories()]);
    ElMessage.success('登录成功');
    loginForm.value = { username: '', password: '' };
  } catch (error) {
    ElMessage.error('登录失败：用户名或密码错误');
  } finally {
    loginLoading.value = false;
  }
};

const logout = () => {
  ElMessageBox.confirm('确定要退出登录吗？', '提示', {
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    type: 'warning'
  }).then(() => {
    localStorage.removeItem('token');
    isLoggedIn.value = false;
    isAdmin.value = false;
    currentUser.value = '';
    files.value = [];
    ElMessage.success('已退出登录');
  }).catch(() => {});
};

// 文件操作相关
const fetchFiles = async () => {
  tableLoading.value = true;
  try {
    const response = await axios.get(`${API_BASE_URL}/files`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
    });
    files.value = response.data;
  } catch (error) {
    ElMessage.error('获取文件列表失败');
  } finally {
    tableLoading.value = false;
  }
};

const downloadFile = async (file) => {
  try {
    const response = await axios.get(`${API_BASE_URL}/download/${file.name}`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
      responseType: 'blob'
    });
    
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', file.originalName || file.name);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
    ElMessage.success('文件下载开始');
  } catch (error) {
    ElMessage.error('下载失败');
  }
};

const deleteFile = async (file) => {
  try {
    await ElMessageBox.confirm(`确定要删除文件 "${file.name}" 吗？`, '警告', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    });
    
    await axios.delete(`${API_BASE_URL}/files/${file.name}`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
    });
    await fetchFiles();
    ElMessage.success('文件删除成功');
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('文件删除失败');
    }
  }
};

// 上传相关
const submitUpload = () => {
  uploadRef.value.submit();
};

const beforeUpload = (file) => {
  if (!selectedCategory.value) {
    ElMessage.warning('请选择文件分类');
    return false;
  }
  return true;
};

const handleUploadSuccess = async () => {
  ElMessage.success('文件上传成功');
  await fetchFiles();
};

const handleUploadError = (error) => {
  console.error('Upload error:', error);
  ElMessage.error('文件上传失败');
};

// 用户注册相关
const showRegisterDialog = () => {
  registerDialogVisible.value = true;
  registerForm.value = { username: '', password: '', role: 'user' };
};

const closeRegisterDialog = () => {
  registerDialogVisible.value = false;
  if (registerFormRef.value) {
    registerFormRef.value.resetFields();
  }
};

const register = async () => {
  if (!registerFormRef.value) return;
  
  await registerFormRef.value.validate(async (valid) => {
    if (valid) {
      registerLoading.value = true;
      try {
        await axios.post(`${API_BASE_URL}/register`, registerForm.value, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        registerDialogVisible.value = false;
        ElMessage.success('用户注册成功');
        registerForm.value = { username: '', password: '', role: 'user' };
      } catch (error) {
        ElMessage.error('用户注册失败');
      } finally {
        registerLoading.value = false;
      }
    }
  });
};

// 分类管理相关
const fetchCategories = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/categories`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
    });
    categories.value = response.data;
  } catch (error) {
    ElMessage.error('获取分类列表失败');
  }
};

const showCategoryDialog = () => {
  categoryDialogVisible.value = true;
  categoryForm.value = { name: '', description: '' };
};

const closeCategoryDialog = () => {
  categoryDialogVisible.value = false;
  if (categoryFormRef.value) {
    categoryFormRef.value.resetFields();
  }
};

const createCategory = async () => {
  if (!categoryFormRef.value) return;
  
  await categoryFormRef.value.validate(async (valid) => {
    if (valid) {
      categoryLoading.value = true;
      try {
        await axios.post(`${API_BASE_URL}/categories`, categoryForm.value, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        await fetchCategories();
        categoryDialogVisible.value = false;
        ElMessage.success('分类创建成功');
        categoryForm.value = { name: '', description: '' };
      } catch (error) {
        ElMessage.error('分类创建失败');
      } finally {
        categoryLoading.value = false;
      }
    }
  });
};

// 工具方法
const getCategoryName = (categoryId) => {
  const category = categories.value.find(c => c.id === categoryId);
  return category ? category.name : '未分类';
};

const formatDate = (date) => {
  return new Date(date).toLocaleString();
};

const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const filterFiles = (category) => {
  currentCategory.value = category;
};
</script>

<style>
.app-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 0;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 15px;
}

.username {
  font-size: 14px;
  color: #606266;
}

.login-container {
  max-width: 400px;
  margin: 100px auto;
  padding: 20px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.login-title {
  text-align: center;
  margin-bottom: 30px;
  color: #303133;
}

.admin-controls {
  display: flex;
  gap: 15px;
  margin-bottom: 20px;
  flex-wrap: wrap;
  align-items: flex-start;
}

.category-filter {
  margin: 20px 0;
}

.el-upload__tip {
  margin-top: 10px;
}

.el-upload__tip .el-select {
  width: 200px;
}

.ml-3 {
  margin-left: 12px;
}

.el-header {
  background-color: #f5f7fa;
  border-bottom: 1px solid #e4e7ed;
  padding: 0;
}

.el-main {
  padding-top: 20px;
}

.upload-demo {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.el-table {
  margin-top: 20px;
}
</style>