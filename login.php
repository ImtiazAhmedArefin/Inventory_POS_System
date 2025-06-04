<?php
session_start();
require_once __DIR__ . '/db_plugin.php';
 // Redirect if already logged in
if (isset($_SESSION['log_user_status']) && $_SESSION['log_user_status'] === true) {
    header("Location: dashboard.php");
    exit();
}

// Handle login attempt
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    // Basic validation
    if (empty($username) || empty($password)) {
        $error = "Username and password are required";
    } else {
        // Get user with login attempt tracking
        $res = $mysqli->common_select('users', 
            'id, username, full_name, email, role, is_active, password, login_attempts, locked_until', 
            ['username' => $username]
        );
        
        if ($res['error'] == 0 && count($res['data']) > 0) {
            $user = $res['data'][0];
            
            // Check if account is locked
            if ($user->locked_until && strtotime($user->locked_until) > time()) {
                $error = "Account locked. Try again later.";
            } else {
                // Verify password
                if (password_verify($password, $user->password)) {
                    // Reset login attempts on successful login
                    $mysqli->common_update('users', 
                        [
                            'login_attempts' => 0,
                            'locked_until' => null,
                            'last_login' => date('Y-m-d H:i:s'),
                            'last_login_ip' => $_SERVER['REMOTE_ADDR']
                        ], 
                        ['id' => $user->id]
                    );
                    
                    if ($user->is_active == 0) {
                        $error = "Your account is not active";
                    } else {
                        // Set session
                        $_SESSION['user'] = $user;
                        $_SESSION['role'] = $user->role;
                        $_SESSION['log_user_status'] = true;
                        
                        // Log successful login
                        $mysqli->common_insert('security_logs', [
                            'user_id' => $user->id,
                            'ip_address' => $_SERVER['REMOTE_ADDR'],
                            'action' => 'login',
                            'details' => 'Successful login',
                            'status' => 'success'
                        ]);
                        
                        header("Location: dashboard.php");
                        exit();
                    }
                } else {
                    // Increment failed login attempts
                    $attempts = $user->login_attempts + 1;
                    $lock_until = null;
                    
                    if ($attempts >= 5) {
                        $lock_until = date('Y-m-d H:i:s', strtotime('+5 minutes'));
                        $error = "Too many failed attempts. Account locked for 5
                         minutes.";
                    } else {
                        $error = "Invalid username or password";
                    }
                    
                    $mysqli->common_update('users', 
                        [
                            'login_attempts' => $attempts,
                            'locked_until' => $lock_until
                        ], 
                        ['id' => $user->id]
                    );
                    
                    // Log failed attempt
                    $mysqli->common_insert('security_logs', [
                        'user_id' => $user->id,
                        'ip_address' => $_SERVER['REMOTE_ADDR'],
                        'action' => 'login',
                        'details' => 'Failed login attempt',
                        'status' => 'failure'
                    ]);
                }
            }
        } else {
            $error = "Invalid username or password";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log In</title>
    <link rel="stylesheet" href="assets/css/new_css.css">
</head>
<body style="background-image: url('assets/img/asd.jpg'); background-size: cover;">
    
<section class="h-100 gradient-form" style="background-color: #eee;">
  <div class="container py-5 h-100">
    <div class="row d-flex justify-content-center align-items-center h-100">
      <div class="col-xl-10">
        <div class="card rounded-3 text-black">
          <div class="row g-0">
            <div class="col-lg-6">
              <div class="card-body p-md-5 mx-md-4">

                <div class="text-center">
                  <img src="https://mdbcdn.b-cdn.net/img/Photos/new-templates/bootstrap-login-form/lotus.webp"
                    style="width: 185px;" alt="logo">
                  <h4 class="mt-1 mb-5 pb-1">We are The Lotus Team</h4>
                </div>

                <form action="" method="post">
                <div class="input-box">
                    <input value="" required="" type="text" name="username" />
                    <label>Username</label>
                </div>
                <div class="input-box">
                    <input value="" required="" type="password" name="password"/>
                    <label>Password</label>
                </div>
                <div class="forgot-pass">
                    <a href="#">Forgot your password?</a>
                </div>
                <button class="btn" type="submit">Login</button>
                </form>

              </div>
            </div>
            <div class="col-lg-6 d-flex align-items-center gradient-custom-2">
              <div class="text-white px-3 py-4 p-md-5 mx-md-4">
                <h4 class="mb-4">We are more than just a company</h4>
                <p class="small mb-0">Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
                  tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud
                  exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>