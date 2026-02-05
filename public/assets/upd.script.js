document.addEventListener('DOMContentLoaded', () => {
  const fileInput = document.getElementById('fileInput');
  const uploadArea = document.getElementById('uploadArea');
  const uploadBtn = document.getElementById('uploadBtn');
  const statusDiv = document.getElementById('status');
  const fileBox = document.getElementById('fileBox');
  const fileName = document.getElementById('fileName');
  const fileSize = document.getElementById('fileSize');
  const removeFileBtn = document.getElementById('removeFile');
  const results = document.getElementById('results');
  const resultOriginal = document.getElementById('resultOriginal');
  const resultUrl = document.getElementById('resultUrl');
  const copyBtn = document.getElementById('copyBtn');
  const btnText = document.getElementById('btnText');
  const btnSpinner = document.getElementById('btnSpinner');
  
  let selectedFile = null;
  let apiKey = '';
  
  function generateRandomKey() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let key = '';
    for (let i = 0; i < 10; i++) {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    apiKey = key;
    return key;
  }
  
  function showStatus(message, isSuccess = true) {
    statusDiv.textContent = message;
    statusDiv.className = isSuccess ?
      'bg-zinc-100 text-zinc-700' :
      'bg-red-100 text-red-700';
    statusDiv.classList.remove('hidden');
    
    setTimeout(() => {
      statusDiv.classList.add('hidden');
    }, 4000);
  }
  
  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
  
  function showFileBox(file) {
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    fileBox.classList.remove('hidden');
    uploadBtn.disabled = false;
  }
  
  function removeFile() {
    selectedFile = null;
    fileInput.value = '';
    fileBox.classList.add('hidden');
    uploadBtn.disabled = true;
    results.classList.add('hidden');
    showStatus('File telah dihapus');
  }
  
  async function uploadFile() {
    if (!selectedFile) return;
    
    btnText.textContent = '';
    btnSpinner.classList.remove('hidden');
    uploadBtn.disabled = true;
    
    try {
      const key = generateRandomKey();
      
      const keyResponse = await fetch('/keys/add', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `key=${key}`
      });
      
      const keyData = await keyResponse.json();
      
      if (!keyData.success) {
        throw new Error('Gagal menyiapkan upload');
      }
      
      const formData = new FormData();
      formData.append('file', selectedFile);
      
      const uploadResponse = await fetch(`/upload?key=${key}`, {
        method: 'POST',
        body: formData
      });
      
      const uploadData = await uploadResponse.json();
      
      btnText.textContent = 'Upload File';
      btnSpinner.classList.add('hidden');
      uploadBtn.disabled = false;
      
      if (uploadData.success) {
        resultOriginal.textContent = uploadData.original;
        resultUrl.textContent = uploadData.url;
        resultUrl.href = uploadData.url;
        results.classList.remove('hidden');
        showStatus('File berhasil diupload!');
      } else {
        throw new Error(uploadData.message || 'Upload gagal');
      }
      
    } catch (error) {
      btnText.textContent = 'Upload File';
      btnSpinner.classList.add('hidden');
      uploadBtn.disabled = false;
      showStatus(`Error: ${error.message}`, false);
    }
  }
  
  function copyToClipboard() {
    const url = resultUrl.href;
    navigator.clipboard.writeText(url).then(() => {
      showStatus('URL berhasil disalin!');
    }).catch(() => {
      showStatus('Gagal menyalin URL', false);
    });
  }
  
  uploadArea.addEventListener('click', () => {
    fileInput.click();
  });
  
  uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('dragover');
  });
  
  uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragover');
  });
  
  uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
    
    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      selectedFile = e.dataTransfer.files[0];
      showFileBox(selectedFile);
      showStatus('File siap diupload');
    }
  });
  
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      selectedFile = fileInput.files[0];
      showFileBox(selectedFile);
      showStatus('File siap diupload');
    }
  });
  
  uploadBtn.addEventListener('click', uploadFile);
  
  removeFileBtn.addEventListener('click', removeFile);
  
  copyBtn.addEventListener('click', copyToClipboard);
  
  generateRandomKey();
});
