const loginSection = document.getElementById('login-section');
const passwordSection = document.getElementById('password-section');
const loginMessage = document.getElementById('login-message');
const passwordMessage = document.getElementById('password-message');

function showMessage(element, text, type) {
  element.textContent = text;
  element.className = 'message ' + type;
}

function clearMessage(element) {
  element.textContent = '';
  element.className = 'message';
}

async function handleLogin() {
  const password = document.getElementById('password').value;
  const loginBtn = document.getElementById('login-btn');
  
  if (!password) {
    showMessage(loginMessage, 'Please enter password', 'error');
    return;
  }
  
  clearMessage(loginMessage);
  loginBtn.disabled = true;
  
  try {
    const response = await fetch('/biubo-cgi/dashboard/api/simple-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await response.json();
    
    if (data.status === 'success') {
      if (data.force_password_change) {
        loginSection.classList.add('hidden');
        passwordSection.classList.remove('hidden');
        document.getElementById('old-password').value = password;
        document.getElementById('old-password').focus();
      } else {
        window.location.href = '/biubo-cgi/dashboard';
      }
    } else {
      showMessage(loginMessage, data.msg || 'Invalid password', 'error');
      loginBtn.disabled = false;
    }
  } catch (error) {
    showMessage(loginMessage, 'Network error, please try again', 'error');
    loginBtn.disabled = false;
  }
}

async function handleChangePassword() {
  const oldPassword = document.getElementById('old-password').value;
  const newPassword = document.getElementById('new-password').value;
  const confirmPassword = document.getElementById('confirm-password').value;
  const changeBtn = document.getElementById('change-password-btn');
  
  if (!oldPassword || !newPassword || !confirmPassword) {
    showMessage(passwordMessage, 'Please fill all fields', 'error');
    return;
  }
  
  if (newPassword !== confirmPassword) {
    showMessage(passwordMessage, 'Passwords do not match', 'error');
    return;
  }
  
  if (newPassword.length < 8) {
    showMessage(passwordMessage, 'Password must be at least 8 characters', 'error');
    return;
  }
  
  clearMessage(passwordMessage);
  changeBtn.disabled = true;
  
  try {
    const response = await fetch('/biubo-cgi/dashboard/api/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        old_password: oldPassword,
        new_password: newPassword,
        confirm_password: confirmPassword
      })
    });
    const data = await response.json();
    
    if (data.status === 'success') {
      showMessage(passwordMessage, 'Password changed successfully! Redirecting...', 'success');
      setTimeout(() => {
        window.location.href = '/biubo-cgi/dashboard';
      }, 1500);
    } else {
      showMessage(passwordMessage, data.msg || 'Failed to change password', 'error');
      changeBtn.disabled = false;
    }
  } catch (error) {
    showMessage(passwordMessage, 'Network error, please try again', 'error');
    changeBtn.disabled = false;
  }
}

document.getElementById('login-btn').addEventListener('click', handleLogin);
document.getElementById('password').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handleLogin();
});

document.getElementById('change-password-btn').addEventListener('click', handleChangePassword);
document.getElementById('confirm-password').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handleChangePassword();
});
