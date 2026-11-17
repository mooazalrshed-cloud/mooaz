<?php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/db.php';

mysqli_set_charset($conn, 'utf8mb4');
header_remove('X-Powered-By');

function json_out(array $data): never {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}
function require_login(): void {
    if (empty($_SESSION['user_id'])) json_out(['status'=>'error','message'=>'يرجى تسجيل الدخول أولاً']);
}
function require_role(array $roles): void {
    require_login();
    if (!in_array($_SESSION['role'] ?? '', $roles, true)) json_out(['status'=>'error','message'=>'ليست لديك صلاحية لتنفيذ هذا الإجراء']);
}
function post_str(string $key, string $default=''): string {
    return trim((string)($_POST[$key] ?? $default));
}
function ensure_table(mysqli $conn, string $sql): void {
    if (!$conn->query($sql)) {
        http_response_code(500);
        exit('تعذر تجهيز جداول النظام. راجع قاعدة البيانات وملف db.php.');
    }
}
ensure_table($conn, "CREATE TABLE IF NOT EXISTS settings (
 id INT AUTO_INCREMENT PRIMARY KEY, setting_key VARCHAR(100) NOT NULL UNIQUE,
 setting_value TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
ensure_table($conn, "CREATE TABLE IF NOT EXISTS users (
 id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(100) NOT NULL UNIQUE,
 password VARCHAR(255) NOT NULL, role VARCHAR(50) NOT NULL DEFAULT 'كاشير',
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
ensure_table($conn, "CREATE TABLE IF NOT EXISTS products (
 id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(190) NOT NULL,
 price DECIMAL(12,2) NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
ensure_table($conn, "CREATE TABLE IF NOT EXISTS invoices (
 id INT AUTO_INCREMENT PRIMARY KEY, invoice_no VARCHAR(50) NOT NULL,
 time_str VARCHAR(40) NOT NULL, items_summary TEXT NOT NULL,
 total DECIMAL(12,2) NOT NULL DEFAULT 0, cashier VARCHAR(100) NOT NULL,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 INDEX idx_invoices_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
ensure_table($conn, "CREATE TABLE IF NOT EXISTS expenses (
 id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(190) NOT NULL,
 amount DECIMAL(12,2) NOT NULL DEFAULT 0, time_str VARCHAR(40) NOT NULL,
 cashier VARCHAR(100) DEFAULT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 INDEX idx_expenses_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

$defaults = ['restaurant_name'=>'مطعم معاذ الذكي','phone'=>'','logo'=>'🍽️'];
foreach ($defaults as $key=>$value) {
    $stmt = $conn->prepare("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)");
    $stmt->bind_param('ss', $key, $value); $stmt->execute(); $stmt->close();
}
/* Create the initial administrator only when the users table is empty.
   Change this password immediately after the first login. */
$countResult = $conn->query("SELECT COUNT(*) AS c FROM users");
if ((int)$countResult->fetch_assoc()['c'] === 0) {
    $username = 'admin';
    $passwordHash = password_hash('ChangeMe123!', PASSWORD_DEFAULT);
    $role = 'مدير عام';
    $stmt = $conn->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)");
    $stmt->bind_param('sss', $username, $passwordHash, $role);
    $stmt->execute(); $stmt->close();
}

if (isset($_GET['action'])) {
    $action = (string)$_GET['action'];
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($action === 'login' && $method === 'POST') {
        $username = post_str('username'); $password = (string)($_POST['password'] ?? '');
        $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username=? LIMIT 1");
        $stmt->bind_param('s', $username); $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc(); $stmt->close();
        $validPassword = $row && password_verify($password, $row['password']);
        // Compatibility for existing installations that stored plain-text passwords:
        // after a successful legacy login, immediately replace it with a password hash.
        if ($row && !$validPassword && hash_equals((string)$row['password'], $password)) {
            $newHash = password_hash($password, PASSWORD_DEFAULT);
            $upgrade = $conn->prepare("UPDATE users SET password=? WHERE id=?");
            $upgrade->bind_param('si', $newHash, $row['id']);
            $upgrade->execute();
            $upgrade->close();
            $validPassword = true;
        }
        if ($validPassword) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int)$row['id'];
            $_SESSION['user'] = $row['username'];
            $_SESSION['role'] = $row['role'];
            json_out(['status'=>'success','user'=>$row['username'],'role'=>$row['role']]);
        }
        json_out(['status'=>'error','message'=>'اسم المستخدم أو كلمة المرور غير صحيحة']);
    }
    if ($action === 'logout' && $method === 'POST') {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time()-42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
        json_out(['status'=>'success']);
    }
    if ($action === 'session') {
        json_out(['logged_in'=>!empty($_SESSION['user_id']),'user'=>$_SESSION['user']??'','role'=>$_SESSION['role']??'']);
    }
    require_login();

    if ($action === 'get_settings') {
        $res=$conn->query("SELECT setting_key, setting_value FROM settings");
        $out=[]; while($r=$res->fetch_assoc()) $out[$r['setting_key']]=$r['setting_value'];
        json_out($out);
    }
    if ($action === 'save_settings' && $method === 'POST') {
        require_role(['مدير عام']);
        foreach (['restaurant_name','phone','logo'] as $key) {
            $value=post_str($key);
            $stmt=$conn->prepare("INSERT INTO settings (setting_key,setting_value) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)");
            $stmt->bind_param('ss',$key,$value); $stmt->execute(); $stmt->close();
        }
        json_out(['status'=>'success']);
    }
    if ($action === 'get_users') {
        require_role(['مدير عام']);
        $res=$conn->query("SELECT id,username,role,created_at FROM users ORDER BY id DESC");
        $out=[]; while($r=$res->fetch_assoc()) $out[]=$r;
        json_out($out);
    }
    if ($action === 'add_user' && $method === 'POST') {
        require_role(['مدير عام']);
        $u=post_str('username'); $p=(string)($_POST['password']??''); $role=post_str('role','كاشير');
        if ($u==='' || strlen($p)<8) json_out(['status'=>'error','message'=>'أدخل اسم المستخدم وكلمة مرور من 8 أحرف على الأقل']);
        if (!in_array($role,['مدير عام','محاسب','كاشير'],true)) $role='كاشير';
        $hash=password_hash($p,PASSWORD_DEFAULT);
        $stmt=$conn->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)");
        $stmt->bind_param('sss',$u,$hash,$role);
        if ($stmt->execute()) json_out(['status'=>'success']);
        json_out(['status'=>'error','message'=>'تعذر إضافة المستخدم؛ ربما اسم المستخدم موجود مسبقاً']);
    }
    if ($action === 'delete_user' && $method === 'POST') {
        require_role(['مدير عام']);
        $id=(int)($_POST['id']??0);
        if ($id<1 || $id===(int)$_SESSION['user_id']) json_out(['status'=>'error','message'=>'لا يمكن حذف هذا المستخدم']);
        $stmt=$conn->prepare("DELETE FROM users WHERE id=?"); $stmt->bind_param('i',$id); $stmt->execute();
        json_out(['status'=>'success']);
    }
    if ($action === 'get_products') {
        $res=$conn->query("SELECT id,name,price FROM products ORDER BY name ASC");
        $out=[]; while($r=$res->fetch_assoc()) $out[]=$r; json_out($out);
    }
    if ($action === 'add_product' && $method === 'POST') {
        require_role(['مدير عام','محاسب']);
        $name=post_str('name'); $price=(float)($_POST['price']??0);
        if ($name==='' || $price<=0) json_out(['status'=>'error','message'=>'أدخل اسم الصنف وسعراً أكبر من صفر']);
        $stmt=$conn->prepare("INSERT INTO products (name,price) VALUES (?,?)"); $stmt->bind_param('sd',$name,$price);
        $stmt->execute(); json_out(['status'=>'success']);
    }
    if ($action === 'edit_product' && $method === 'POST') {
        require_role(['مدير عام','محاسب']);
        $id=(int)($_POST['id']??0); $name=post_str('name'); $price=(float)($_POST['price']??0);
        if ($id<1 || $name==='' || $price<=0) json_out(['status'=>'error','message'=>'تحقق من بيانات الصنف']);
        $stmt=$conn->prepare("UPDATE products SET name=?,price=? WHERE id=?"); $stmt->bind_param('sdi',$name,$price,$id); $stmt->execute();
        json_out(['status'=>'success']);
    }
    if ($action === 'delete_product' && $method === 'POST') {
        require_role(['مدير عام','محاسب']);
        $id=(int)($_POST['id']??0); if($id<1) json_out(['status'=>'error','message'=>'رقم الصنف غير صحيح']);
        $stmt=$conn->prepare("DELETE FROM products WHERE id=?"); $stmt->bind_param('i',$id); $stmt->execute();
        json_out(['status'=>'success']);
    }
    if ($action === 'checkout' && $method === 'POST') {
        require_role(['مدير عام','كاشير']);
        $itemsRaw=json_decode((string)($_POST['items']??'[]'),true);
        if (!is_array($itemsRaw) || !$itemsRaw) json_out(['status'=>'error','message'=>'الفاتورة فارغة']);
        $ids=[]; foreach($itemsRaw as $it) { $id=(int)($it['id']??0); $qty=(int)($it['qty']??0); if($id>0 && $qty>0 && $qty<=1000) $ids[$id]=($ids[$id]??0)+$qty; }
        if (!$ids) json_out(['status'=>'error','message'=>'الأصناف أو الكميات غير صحيحة']);
        $conn->begin_transaction();
        try {
            $stmt=$conn->prepare("SELECT id,name,price FROM products WHERE id=?");
            $items=[]; $total=0.0;
            foreach($ids as $id=>$qty) {
                $stmt->bind_param('i',$id); $stmt->execute(); $p=$stmt->get_result()->fetch_assoc();
                if(!$p) throw new RuntimeException('أحد الأصناف لم يعد موجوداً');
                $items[]=['name'=>$p['name'],'qty'=>$qty,'price'=>(float)$p['price']];
                $total+=(float)$p['price']*$qty;
            }
            $stmt->close();
            $invoiceNo='MZ-'.date('YmdHis').'-'.random_int(100,999);
            $timeStr=date('Y-m-d H:i:s'); $summaryParts=[];
            foreach($items as $it) $summaryParts[]=$it['name'].' × '.$it['qty'];
            $summary=implode('، ',$summaryParts); $cashier=(string)$_SESSION['user'];
            $stmt=$conn->prepare("INSERT INTO invoices (invoice_no,time_str,items_summary,total,cashier) VALUES (?,?,?,?,?)");
            $stmt->bind_param('sssds',$invoiceNo,$timeStr,$summary,$total,$cashier); $stmt->execute(); $invoiceId=$conn->insert_id; $stmt->close();
            $conn->commit();
            json_out(['status'=>'success','insert_id'=>$invoiceId,'invoice_no'=>$invoiceNo,'total'=>$total]);
        } catch(Throwable $e) {
            $conn->rollback(); json_out(['status'=>'error','message'=>'لم يتم حفظ الفاتورة: '.$e->getMessage()]);
        }
    }
    if ($action === 'get_invoices') {
        require_role(['مدير عام','محاسب']);
        $res=$conn->query("SELECT id,invoice_no,time_str,items_summary,total,cashier,created_at FROM invoices ORDER BY id DESC LIMIT 500");
        $out=[]; while($r=$res->fetch_assoc()) $out[]=$r; json_out($out);
    }
    if ($action === 'delete_invoice' && $method === 'POST') {
        require_role(['مدير عام']);
        $id=(int)($_POST['id']??0); if($id<1) json_out(['status'=>'error','message'=>'رقم الفاتورة غير صحيح']);
        $stmt=$conn->prepare("DELETE FROM invoices WHERE id=?"); $stmt->bind_param('i',$id); $stmt->execute();
        json_out(['status'=>'success']);
    }
    if ($action === 'add_expense' && $method === 'POST') {
        require_role(['مدير عام','محاسب']);
        $title=post_str('title'); $amount=(float)($_POST['amount']??0);
        if($title==='' || $amount<=0) json_out(['status'=>'error','message'=>'أدخل بيان المصروف ومبلغاً أكبر من صفر']);
        $timeStr=date('Y-m-d H:i:s'); $cashier=(string)$_SESSION['user'];
        $stmt=$conn->prepare("INSERT INTO expenses (title,amount,time_str,cashier) VALUES (?,?,?,?)");
        $stmt->bind_param('sdss',$title,$amount,$timeStr,$cashier); $stmt->execute();
        json_out(['status'=>'success']);
    }
    if ($action === 'get_expenses') {
        require_role(['مدير عام','محاسب']);
        $res=$conn->query("SELECT id,title,amount,time_str,cashier,created_at FROM expenses ORDER BY id DESC LIMIT 500");
        $out=[]; while($r=$res->fetch_assoc()) $out[]=$r; json_out($out);
    }
    if ($action === 'delete_expense' && $method === 'POST') {
        require_role(['مدير عام']);
        $id=(int)($_POST['id']??0); if($id<1) json_out(['status'=>'error','message'=>'رقم المصروف غير صحيح']);
        $stmt=$conn->prepare("DELETE FROM expenses WHERE id=?"); $stmt->bind_param('i',$id); $stmt->execute();
        json_out(['status'=>'success']);
    }
    if ($action === 'get_summary') {
        require_role(['مدير عام','محاسب']);
        $period=post_str('period','day');
        $where=$period==='month' ? "DATE_FORMAT(created_at,'%Y-%m')=DATE_FORMAT(CURDATE(),'%Y-%m')" : "DATE(created_at)=CURDATE()";
        $sales=(float)$conn->query("SELECT COALESCE(SUM(total),0) n FROM invoices WHERE $where")->fetch_assoc()['n'];
        $invoiceCount=(int)$conn->query("SELECT COUNT(*) n FROM invoices WHERE $where")->fetch_assoc()['n'];
        $expenses=(float)$conn->query("SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE $where")->fetch_assoc()['n'];
        json_out(['sales'=>$sales,'invoice_count'=>$invoiceCount,'expenses'=>$expenses,'net'=>$sales-$expenses,'period'=>$period]);
    }
    json_out(['status'=>'error','message'=>'الطلب غير معروف']);
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>معاذ الذكي | إدارة المطاعم</title>
<style>
:root{--green:#263b35;--green2:#344e43;--gold:#b99a5b;--cream:#f5f1e8;--paper:#fffdf8;--ink:#26332d;--muted:#788078;--line:#e5dfd2;--red:#a9473f;--shadow:0 5px 18px rgba(38,59,53,.07)}
*{box-sizing:border-box}body{margin:0;font-family:Tahoma,Arial,sans-serif;background:var(--cream);color:var(--ink);font-size:14px}button,input,select{font:inherit}button{cursor:pointer}.hidden{display:none!important}
#toast-container{position:fixed;top:18px;left:18px;z-index:1000;display:grid;gap:8px}.toast{padding:13px 18px;border-radius:9px;background:var(--green);color:white;box-shadow:var(--shadow);max-width:340px}.toast.error{background:var(--red)}
.login-screen{min-height:100vh;display:grid;place-items:center;padding:20px;background:linear-gradient(135deg,#1f302b,#344e43)}.login-card{width:min(410px,100%);background:var(--paper);border-radius:16px;padding:32px;box-shadow:0 20px 60px #0003}.brand-mark{width:62px;height:62px;margin:0 auto 14px;display:grid;place-items:center;border-radius:16px;background:var(--green);color:var(--gold);font-size:30px}.login-card h1{text-align:center;margin:0;color:var(--green);font-size:25px}.login-card p{text-align:center;color:var(--muted);margin:9px 0 25px}
.field{display:grid;gap:7px;margin-bottom:15px}.field label{font-weight:bold;color:#536057}.field input,.field select,.field textarea,input.control{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:8px;background:white;color:var(--ink);outline:none}.field input:focus,.field select:focus,input.control:focus{border-color:var(--gold);box-shadow:0 0 0 3px #b99a5b22}
.btn{border:0;border-radius:8px;padding:10px 15px;font-weight:bold;display:inline-flex;align-items:center;justify-content:center;gap:7px}.btn-primary{background:var(--green);color:white}.btn-gold{background:var(--gold);color:#fff}.btn-light{background:#eee8db;color:var(--green)}.btn-danger{background:#f7e7e4;color:var(--red)}.btn-small{padding:6px 9px;font-size:12px}.full{width:100%}
#main-app{min-height:100vh}.layout{display:flex;min-height:100vh}.sidebar{width:245px;background:var(--green);color:white;display:flex;flex-direction:column;flex-shrink:0}.sidebar-head{padding:24px 18px;border-bottom:1px solid #ffffff1c;text-align:center}.sidebar-head .logo{font-size:27px;color:var(--gold)}.sidebar-head h2{font-size:20px;margin:8px 0 4px}.sidebar-head small{color:#c9d3cc}.nav{padding:14px 10px;display:grid;gap:5px;flex:1}.nav button{border:0;background:transparent;color:#d7dfd9;text-align:right;padding:12px 13px;border-radius:8px;display:flex;align-items:center;gap:10px}.nav button:hover,.nav button.active{background:#ffffff17;color:#fff;border-right:3px solid var(--gold)}.sidebar-foot{padding:16px;border-top:1px solid #ffffff1c}.sidebar-foot small{color:#c9d3cc}.sidebar-foot strong{display:block;margin:7px 0}
.main{flex:1;min-width:0}.topbar{height:72px;background:var(--paper);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 27px;gap:15px}.topbar h1{font-size:19px;margin:0;color:var(--green)}.top-meta{display:flex;align-items:center;gap:12px;color:var(--muted)}.status{display:inline-flex;align-items:center;gap:7px;padding:7px 11px;border-radius:20px;background:#e4eee6;color:#2c6846;font-size:12px;font-weight:bold}.status.closed{background:#f5e5e1;color:var(--red)}
.content{padding:25px;max-width:1600px;margin:auto}.page{display:none}.page.active{display:block}.page-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:20px}.page-heading h2{font-size:22px;margin:0;color:var(--green)}.page-heading p{margin:6px 0 0;color:var(--muted)}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px;margin-bottom:20px}.kpi,.panel{background:var(--paper);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}.kpi{padding:19px;border-top:3px solid var(--gold)}.kpi .label{color:var(--muted);font-size:13px}.kpi .value{font-size:23px;font-weight:bold;color:var(--green);margin-top:10px;overflow-wrap:anywhere}.kpi .sub{font-size:11px;color:var(--muted);margin-top:6px}.dashboard-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.panel{padding:20px;margin-bottom:18px;min-width:0}.panel-title{display:flex;justify-content:space-between;align-items:center;gap:10px;padding-bottom:13px;border-bottom:1px solid var(--line);margin-bottom:16px}.panel-title h3{font-size:16px;margin:0;color:var(--green)}
.actions{display:flex;gap:9px;flex-wrap:wrap}.inline-form{display:flex;align-items:end;gap:12px;flex-wrap:wrap}.inline-form .field{flex:1;min-width:150px;margin:0}.table-wrap{width:100%;overflow:auto}table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:right;padding:12px 11px;border-bottom:1px solid var(--line);font-size:13px}th{background:#f4f0e7;color:#59645b;font-weight:bold}tbody tr:hover{background:#faf7f0}.empty{text-align:center;color:var(--muted);padding:28px}
.pos-layout{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(300px,.8fr);gap:18px;align-items:start}.products-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(135px,1fr));gap:12px}.product-card{border:1px solid var(--line);background:#fff;border-radius:10px;padding:15px 10px;text-align:center;color:var(--ink);min-height:110px}.product-card:hover{border-color:var(--gold);box-shadow:var(--shadow)}.product-card .emoji{font-size:25px;margin-bottom:9px}.product-card strong{display:block;overflow-wrap:anywhere}.product-card span{display:block;margin-top:8px;color:var(--green);font-weight:bold}.cart-panel{position:sticky;top:15px}.cart-line{display:grid;grid-template-columns:1fr auto;gap:8px;padding:12px 0;border-bottom:1px solid var(--line)}.qty-controls{display:flex;align-items:center;gap:7px;margin-top:7px}.qty-controls button{width:27px;height:27px;border:1px solid var(--line);border-radius:6px;background:#f7f3eb}.cart-total{display:flex;justify-content:space-between;font-size:19px;font-weight:bold;padding:18px 0;color:var(--green)}
@media(max-width:1000px){.sidebar{width:210px}.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.dashboard-grid{grid-template-columns:1fr}.pos-layout{grid-template-columns:1fr}.cart-panel{position:static}}
@media(max-width:700px){.layout{display:block}.sidebar{width:100%;min-height:0}.sidebar-head{padding:13px}.sidebar-head .logo{display:none}.sidebar-head h2{margin:0}.nav{display:flex;overflow:auto;padding:8px}.nav button{white-space:nowrap;padding:10px}.sidebar-foot{display:none}.topbar{height:auto;padding:14px;align-items:flex-start;flex-direction:column}.content{padding:13px}.kpis{gap:9px}.kpi{padding:13px}.kpi .value{font-size:18px}.page-heading{align-items:flex-start;flex-direction:column}.panel{padding:14px}.login-card{padding:24px}}
</style>
</head>
<body>
<div id="toast-container"></div>
<section id="login-screen" class="login-screen">
 <form class="login-card" id="login-form">
  <div class="brand-mark">🍽</div><h1 id="login-name">معاذ الذكي</h1><p>نظام إدارة المطاعم ونقاط البيع</p>
  <div class="field"><label for="login-user">اسم المستخدم</label><input id="login-user" autocomplete="username" required></div>
  <div class="field"><label for="login-pass">كلمة المرور</label><input id="login-pass" type="password" autocomplete="current-password" required></div>
  <button class="btn btn-primary full" type="submit">تسجيل الدخول</button>
  <small style="display:block;text-align:center;color:#8a8f87;margin-top:15px">لأول تشغيل فقط: admin / ChangeMe123!</small>
 </form>
</section>
<section id="main-app" class="hidden">
 <div class="layout">
  <aside class="sidebar">
   <div class="sidebar-head"><div class="logo" id="brand-logo">🍽️</div><h2 id="sidebar-name">معاذ الذكي</h2><small>إدارة المطاعم باحتراف</small></div>
   <nav class="nav" id="navigation">
    <button class="active" data-page="dashboard">▦ <span>لوحة التحكم</span></button>
    <button data-page="pos">🛒 <span>نقطة البيع</span></button>
    <button data-page="products">▤ <span>إدارة المنتجات</span></button>
    <button data-page="sales">▧ <span>سجل المبيعات</span></button>
    <button data-page="expenses">− <span>المصروفات</span></button>
    <button data-page="reports">▥ <span>التقارير اليومية والشهرية</span></button>
    <button data-page="settings">⚙ <span>الإعدادات والمستخدمون</span></button>
   </nav>
   <div class="sidebar-foot"><small>المستخدم الحالي</small><strong id="side-user">—</strong><small id="side-role">—</small><button class="btn btn-light full" style="margin-top:13px" id="logout-btn">تسجيل الخروج ↗</button></div>
  </aside>
  <main class="main">
   <header class="topbar"><h1 id="page-title">لوحة التحكم</h1><div class="top-meta"><span id="clock"></span><span id="role-pill" class="status">متصل</span></div></header>
   <div class="content">
    <section class="page active" id="page-dashboard">
     <div class="page-heading"><div><h2>ملخص العمل</h2><p>نظرة سريعة على حركة المطعم اليوم.</p></div><button class="btn btn-light" id="refresh-dashboard">↻ تحديث البيانات</button></div>
     <div class="kpis">
      <div class="kpi"><div class="label">مبيعات اليوم</div><div class="value" id="dash-sales">0 ج.س</div><div class="sub">إجمالي الفواتير المحفوظة اليوم</div></div>
      <div class="kpi"><div class="label">فواتير اليوم</div><div class="value" id="dash-count">0</div><div class="sub">عدد عمليات البيع</div></div>
      <div class="kpi"><div class="label">مصروفات اليوم</div><div class="value" id="dash-expenses">0 ج.س</div><div class="sub">المصروفات المسجلة اليوم</div></div>
      <div class="kpi"><div class="label">الصافي التقديري</div><div class="value" id="dash-net">0 ج.س</div><div class="sub">المبيعات ناقص المصروفات</div></div>
     </div>
     <div class="dashboard-grid">
      <div class="panel"><div class="panel-title"><h3>اختصارات سريعة</h3></div><div class="actions"><button class="btn btn-primary" data-goto="pos">＋ فاتورة جديدة</button><button class="btn btn-light" data-goto="products">＋ إضافة منتج</button><button class="btn btn-light" data-goto="reports">عرض التقارير</button></div><div style="margin-top:18px;color:var(--muted);line-height:1.9">ابدأ الوردية من زر الحالة أدناه، ثم افتح نقطة البيع لتسجيل الفواتير.</div></div>
      <div class="panel"><div class="panel-title"><h3>حالة الوردية</h3><span id="shift-badge" class="status closed">مغلقة</span></div><p style="color:var(--muted);line-height:1.9;margin-bottom:15px" id="shift-description">الوردية مغلقة. افتح الوردية قبل بدء البيع.</p><button id="shift-toggle" class="btn btn-primary">فتح الوردية</button><small style="display:block;color:var(--muted);margin-top:10px">حالة الوردية محفوظة على هذا المتصفح فقط في هذا الإصدار.</small></div>
     </div>
     <div class="panel"><div class="panel-title"><h3>أحدث الفواتير</h3><button class="btn btn-light btn-small" data-goto="sales">عرض الكل</button></div><div class="table-wrap"><table><thead><tr><th>رقم الفاتورة</th><th>التاريخ والوقت</th><th>الأصناف</th><th>الإجمالي</th><th>الكاشير</th></tr></thead><tbody id="recent-sales"></tbody></table></div></div>
    </section>
    <section class="page" id="page-pos">
     <div class="page-heading"><div><h2>نقطة البيع</h2><p>اختر المنتجات لإضافتها إلى الفاتورة الحالية.</p></div><span id="pos-shift" class="status closed">الوردية مغلقة</span></div>
     <div class="pos-layout">
      <div class="panel"><div class="panel-title"><h3>قائمة المنتجات</h3><input class="control" style="max-width:240px" id="product-search" placeholder="بحث عن منتج..."></div><div class="products-grid" id="pos-products"></div></div>
      <div class="panel cart-panel"><div class="panel-title"><h3>الفاتورة الحالية</h3><button id="clear-cart" class="btn btn-danger btn-small">تفريغ</button></div><div id="cart-items"><div class="empty">لم تتم إضافة أصناف بعد.</div></div><div class="cart-total"><span>الإجمالي</span><span id="cart-total">0 ج.س</span></div><button id="checkout-btn" class="btn btn-primary full">إتمام البيع وحفظ الفاتورة</button></div>
     </div>
    </section>
    <section class="page" id="page-products">
     <div class="page-heading"><div><h2>إدارة المنتجات</h2><p>إضافة الأصناف وتحديث أسعارها.</p></div></div>
     <div class="panel"><div class="panel-title"><h3 id="product-form-title">إضافة منتج جديد</h3></div><form id="product-form" class="inline-form"><input type="hidden" id="product-id"><div class="field"><label for="product-name">اسم المنتج</label><input id="product-name" required maxlength="190" placeholder="مثلاً: شاورما دجاج"></div><div class="field"><label for="product-price">السعر بالجنيه السوداني</label><input id="product-price" type="number" min="0.01" step="0.01" required placeholder="0.00"></div><button class="btn btn-primary" type="submit" id="product-save">حفظ المنتج</button><button class="btn btn-light hidden" type="button" id="product-cancel">إلغاء التعديل</button></form></div>
     <div class="panel"><div class="panel-title"><h3>الأصناف المسجلة</h3><span id="products-count" class="status">0 صنف</span></div><div class="table-wrap"><table><thead><tr><th>#</th><th>اسم المنتج</th><th>السعر</th><th>الإجراءات</th></tr></thead><tbody id="products-table"></tbody></table></div></div>
    </section>
    <section class="page" id="page-sales">
     <div class="page-heading"><div><h2>سجل المبيعات</h2><p>مراجعة الفواتير المحفوظة في قاعدة البيانات.</p></div><button class="btn btn-light" id="refresh-sales">↻ تحديث</button></div>
     <div class="panel"><div class="table-wrap"><table><thead><tr><th>رقم الفاتورة</th><th>التاريخ والوقت</th><th>الأصناف والكميات</th><th>الإجمالي</th><th>الكاشير</th><th>الإجراء</th></tr></thead><tbody id="sales-table"></tbody></table></div></div>
    </section>
    <section class="page" id="page-expenses">
     <div class="page-heading"><div><h2>المصروفات</h2><p>تسجيل ومراجعة مصروفات المطعم.</p></div></div>
     <div class="panel"><div class="panel-title"><h3>تسجيل مصروف جديد</h3></div><form id="expense-form" class="inline-form"><div class="field"><label for="expense-title">بيان المصروف</label><input id="expense-title" required maxlength="190" placeholder="مثلاً: شراء مستلزمات"></div><div class="field"><label for="expense-amount">المبلغ بالجنيه السوداني</label><input id="expense-amount" type="number" min="0.01" step="0.01" required placeholder="0.00"></div><button class="btn btn-primary" type="submit">حفظ المصروف</button></form></div>
     <div class="panel"><div class="panel-title"><h3>سجل المصروفات</h3></div><div class="table-wrap"><table><thead><tr><th>#</th><th>بيان المصروف</th><th>المبلغ</th><th>التاريخ والوقت</th><th>المستخدم</th><th>الإجراء</th></tr></thead><tbody id="expenses-table"></tbody></table></div></div>
    </section>
    <section class="page" id="page-reports">
     <div class="page-heading"><div><h2>التقارير المالية</h2><p>ملخص يومي أو شهري للمبيعات والمصروفات.</p></div></div>
     <div class="panel"><div class="inline-form"><div class="field"><label for="report-period">الفترة</label><select id="report-period"><option value="day">تقرير اليوم</option><option value="month">تقرير الشهر الحالي</option></select></div><button class="btn btn-primary" id="run-report">عرض التقرير</button></div></div>
     <div class="kpis"><div class="kpi"><div class="label">إجمالي المبيعات</div><div class="value" id="report-sales">0 ج.س</div></div><div class="kpi"><div class="label">عدد الفواتير</div><div class="value" id="report-count">0</div></div><div class="kpi"><div class="label">إجمالي المصروفات</div><div class="value" id="report-expenses">0 ج.س</div></div><div class="kpi"><div class="label">الصافي التقديري</div><div class="value" id="report-net">0 ج.س</div></div></div>
     <p style="color:var(--muted);line-height:1.8">الصافي هنا هو المبيعات ناقص المصروفات المسجلة، وليس ربحاً محاسبياً نهائياً؛ لأنه لا يشمل تكلفة المخزون أو الالتزامات الأخرى.</p>
    </section>
    <section class="page" id="page-settings">
     <div class="page-heading"><div><h2>الإعدادات والمستخدمون</h2><p>تخصيص بيانات المطعم وإدارة حسابات الموظفين.</p></div></div>
     <div class="panel" id="settings-panel"><div class="panel-title"><h3>بيانات المطعم</h3></div><form id="settings-form" class="inline-form"><div class="field"><label for="setting-name">اسم المطعم</label><input id="setting-name" required></div><div class="field"><label for="setting-phone">رقم الهاتف</label><input id="setting-phone"></div><div class="field"><label for="setting-logo">الشعار أو الرمز</label><input id="setting-logo" maxlength="30"></div><button class="btn btn-primary" type="submit">حفظ الإعدادات</button></form></div>
     <div class="panel" id="users-panel"><div class="panel-title"><h3>إضافة مستخدم</h3></div><form id="user-form" class="inline-form"><div class="field"><label for="new-username">اسم المستخدم</label><input id="new-username" required maxlength="100"></div><div class="field"><label for="new-password">كلمة المرور (8 أحرف على الأقل)</label><input id="new-password" type="password" required minlength="8"></div><div class="field"><label for="new-role">الصلاحية</label><select id="new-role"><option value="كاشير">كاشير</option><option value="محاسب">محاسب</option><option value="مدير عام">مدير عام</option></select></div><button class="btn btn-primary" type="submit">إضافة مستخدم</button></form><div class="table-wrap" style="margin-top:20px"><table><thead><tr><th>#</th><th>اسم المستخدم</th><th>الصلاحية</th><th>الإجراء</th></tr></thead><tbody id="users-table"></tbody></table></div></div>
    </section>
   </div>
  </main>
 </div>
</section>
<script>
const $=id=>document.getElementById(id);
let currentUser=null,currentRole=null,products=[],cart={},isShiftOpen=localStorage.getItem('maaz_shift_open')==='1';
const money=n=>new Intl.NumberFormat('en-US',{maximumFractionDigits:2}).format(Number(n)||0)+' ج.س';
function toast(msg,type='success'){const e=document.createElement('div');e.className='toast '+(type==='error'?'error':'');e.textContent=msg;$('toast-container').appendChild(e);setTimeout(()=>e.remove(),3500)}
async function api(action,data=null){const opts=data?{method:'POST',body:data}:{};const res=await fetch('index.php?action='+encodeURIComponent(action),opts);let out;try{out=await res.json()}catch(e){throw new Error('تعذر قراءة رد الخادم؛ تحقق من أخطاء PHP وملف db.php')}if(res.status===401||out.status==='error'&&out.message==='يرجى تسجيل الدخول أولاً'){logout(false);throw new Error('انتهت الجلسة، سجل الدخول مرة أخرى')}if(out.status==='error')throw new Error(out.message||'حدث خطأ');return out}
function fd(obj){const d=new FormData();Object.entries(obj).forEach(([k,v])=>d.append(k,v));return d}
function safe(text){return String(text??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function can(roles){return roles.includes(currentRole)}
function setRoleUI(){document.querySelectorAll('[data-page="settings"]').forEach(b=>b.classList.toggle('hidden',!can(['مدير عام'])));$('settings-panel').classList.toggle('hidden',!can(['مدير عام']));$('users-panel').classList.toggle('hidden',!can(['مدير عام']));document.querySelectorAll('[data-page="sales"]').forEach(b=>b.classList.toggle('hidden',!can(['مدير عام','محاسب'])));document.querySelectorAll('[data-page="reports"]').forEach(b=>b.classList.toggle('hidden',!can(['مدير عام','محاسب'])));document.querySelectorAll('[data-page="expenses"]').forEach(b=>b.classList.toggle('hidden',!can(['مدير عام','محاسب'])));document.querySelectorAll('[data-page="products"]').forEach(b=>b.classList.toggle('hidden',!can(['مدير عام','محاسب'])));$('side-user').textContent=currentUser;$('side-role').textContent='الصلاحية: '+currentRole;$('role-pill').textContent=currentRole}
function showPage(name){if(name==='settings'&&!can(['مدير عام']))return toast('ليست لديك صلاحية','error');if(['sales','reports','expenses'].includes(name)&&!can(['مدير عام','محاسب']))return toast('ليست لديك صلاحية','error');if(name==='products'&&!can(['مدير عام','محاسب','كاشير']))return toast('ليست لديك صلاحية','error');document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+name));document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===name));const btn=document.querySelector('[data-page="'+name+'"]');$('page-title').textContent=btn?btn.innerText.trim():name;if(name==='products')loadProducts();if(name==='pos')loadProducts();if(name==='sales')loadSales();if(name==='expenses')loadExpenses();if(name==='settings'){loadSettings();if(can(['مدير عام']))loadUsers()}if(name==='reports')runReport()}
function shiftUI(){const badge=$('shift-badge'),pos=$('pos-shift');badge.textContent=isShiftOpen?'مفتوحة':'مغلقة';badge.className='status '+(isShiftOpen?'':'closed');pos.textContent=isShiftOpen?'الوردية مفتوحة':'الوردية مغلقة';pos.className='status '+(isShiftOpen?'':'closed');$('shift-description').textContent=isShiftOpen?'الوردية مفتوحة ويمكن تسجيل المبيعات.':'الوردية مغلقة. افتح الوردية قبل بدء البيع.';$('shift-toggle').textContent=isShiftOpen?'قفل الوردية':'فتح الوردية';$('shift-toggle').className='btn '+(isShiftOpen?'btn-danger':'btn-primary')}
$('shift-toggle').onclick=()=>{isShiftOpen=!isShiftOpen;localStorage.setItem('maaz_shift_open',isShiftOpen?'1':'0');shiftUI();toast(isShiftOpen?'تم فتح الوردية':'تم قفل الوردية')};
function loginUI(user,role){currentUser=user;currentRole=role;$('login-screen').classList.add('hidden');$('main-app').classList.remove('hidden');setRoleUI();shiftUI();showPage('dashboard');loadSettings();loadProducts();loadDashboard();if(can(['مدير عام','محاسب'])){loadSales();loadExpenses()}}
$('login-form').addEventListener('submit',async e=>{e.preventDefault();try{const d=await api('login',fd({username:$('login-user').value.trim(),password:$('login-pass').value}));loginUI(d.user,d.role);toast('مرحباً بك في معاذ الذكي')}catch(err){toast(err.message,'error')}});
async function logout(callServer=true){if(callServer){try{await api('logout',fd({}))}catch(e){}}currentUser=null;currentRole=null;cart={};$('main-app').classList.add('hidden');$('login-screen').classList.remove('hidden');$('login-pass').value=''}
$('logout-btn').onclick=()=>logout();document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.page)));document.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.goto)));
async function loadSettings(){try{const d=await api('get_settings');$('sidebar-name').textContent=d.restaurant_name||'معاذ الذكي';$('login-name').textContent=d.restaurant_name||'معاذ الذكي';$('brand-logo').textContent=d.logo||'🍽️';document.title=(d.restaurant_name||'معاذ الذكي')+' | إدارة المطاعم';$('setting-name').value=d.restaurant_name||'';$('setting-phone').value=d.phone||'';$('setting-logo').value=d.logo||''}catch(e){toast(e.message,'error')}}
$('settings-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('save_settings',fd({restaurant_name:$('setting-name').value.trim(),phone:$('setting-phone').value.trim(),logo:$('setting-logo').value.trim()}));await loadSettings();toast('تم حفظ الإعدادات')}catch(err){toast(err.message,'error')}});
async function loadUsers(){if(!can(['مدير عام']))return;try{const data=await api('get_users');$('users-table').innerHTML=data.map((u,i)=>`<tr><td>${i+1}</td><td>${safe(u.username)}</td><td>${safe(u.role)}</td><td>${Number(u.id)===Number(window.currentUserId)?'الحساب الحالي':`<button class="btn btn-danger btn-small" onclick="deleteUser(${Number(u.id)})">حذف</button>`}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">لا يوجد مستخدمون</td></tr>'}catch(e){toast(e.message,'error')}}
$('user-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('add_user',fd({username:$('new-username').value.trim(),password:$('new-password').value,role:$('new-role').value}));$('user-form').reset();loadUsers();toast('تمت إضافة المستخدم')}catch(err){toast(err.message,'error')}});
async function deleteUser(id){if(!confirm('هل تريد حذف هذا المستخدم؟'))return;try{await api('delete_user',fd({id}));loadUsers();toast('تم حذف المستخدم')}catch(e){toast(e.message,'error')}}
async function loadProducts(){try{products=await api('get_products');renderProducts();renderProductTable()}catch(e){toast(e.message,'error')}}
function renderProducts(){const q=($('product-search').value||'').trim().toLowerCase();const filtered=products.filter(p=>p.name.toLowerCase().includes(q));$('pos-products').innerHTML=filtered.map(p=>`<button class="product-card" onclick="addCart(${Number(p.id)})"><div class="emoji">🍽️</div><strong>${safe(p.name)}</strong><span>${money(p.price)}</span></button>`).join('')||'<div class="empty">لا توجد منتجات مطابقة. أضف منتجات من صفحة إدارة المنتجات.</div>'}
$('product-search').addEventListener('input',renderProducts);
function renderProductTable(){$('products-count').textContent=products.length+' صنف';$('products-table').innerHTML=products.map((p,i)=>`<tr><td>${i+1}</td><td>${safe(p.name)}</td><td>${money(p.price)}</td><td>${can(['مدير عام','محاسب'])?`<button class="btn btn-light btn-small" onclick="editProduct(${Number(p.id)})">تعديل</button> <button class="btn btn-danger btn-small" onclick="deleteProduct(${Number(p.id)})">حذف</button>`:'—'}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">لا توجد منتجات حتى الآن</td></tr>'}
$('product-form').addEventListener('submit',async e=>{e.preventDefault();const id=$('product-id').value;try{await api(id?'edit_product':'add_product',fd({id,name:$('product-name').value.trim(),price:$('product-price').value}));resetProductForm();await loadProducts();toast(id?'تم تعديل المنتج':'تمت إضافة المنتج')}catch(err){toast(err.message,'error')}});
function editProduct(id){const p=products.find(x=>Number(x.id)===id);if(!p)return;$('product-id').value=p.id;$('product-name').value=p.name;$('product-price').value=p.price;$('product-form-title').textContent='تعديل بيانات المنتج';$('product-save').textContent='حفظ التعديل';$('product-cancel').classList.remove('hidden');$('product-name').focus()}
function resetProductForm(){$('product-form').reset();$('product-id').value='';$('product-form-title').textContent='إضافة منتج جديد';$('product-save').textContent='حفظ المنتج';$('product-cancel').classList.add('hidden')}
$('product-cancel').onclick=resetProductForm;
async function deleteProduct(id){if(!confirm('حذف هذا المنتج؟'))return;try{await api('delete_product',fd({id}));await loadProducts();toast('تم حذف المنتج')}catch(e){toast(e.message,'error')}}
function addCart(id){if(!isShiftOpen)return toast('افتح الوردية أولاً','error');const p=products.find(x=>Number(x.id)===id);if(!p)return;if(cart[id])cart[id].qty++;else cart[id]={id:Number(p.id),name:p.name,price:Number(p.price),qty:1};renderCart()}
function renderCart(){const entries=Object.values(cart);$('cart-items').innerHTML=entries.map(i=>`<div class="cart-line"><div><strong>${safe(i.name)}</strong><div style="font-size:12px;color:var(--muted);margin-top:5px">${money(i.price)} × ${i.qty}</div></div><div class="qty-controls"><button onclick="changeQty(${i.id},-1)">−</button><b>${i.qty}</b><button onclick="changeQty(${i.id},1)">+</button></div></div>`).join('')||'<div class="empty">لم تتم إضافة أصناف بعد.</div>';$('cart-total').textContent=money(entries.reduce((s,i)=>s+i.price*i.qty,0))}
function changeQty(id,delta){if(!cart[id])return;cart[id].qty+=delta;if(cart[id].qty<=0)delete cart[id];renderCart()}
$('clear-cart').onclick=()=>{cart={};renderCart()};
$('checkout-btn').onclick=async()=>{if(!isShiftOpen)return toast('افتح الوردية أولاً','error');const items=Object.values(cart).map(i=>({id:i.id,qty:i.qty}));if(!items.length)return toast('الفاتورة فارغة','error');if(!confirm('تأكيد إتمام البيع بمبلغ '+$('cart-total').textContent+'؟'))return;try{const d=await api('checkout',fd({items:JSON.stringify(items)}));cart={};renderCart();toast('تم حفظ الفاتورة '+d.invoice_no);loadDashboard();if(can(['مدير عام','محاسب']))loadSales()}catch(e){toast(e.message,'error')}};
async function loadSales(){if(!can(['مدير عام','محاسب']))return;try{const data=await api('get_invoices');const rows=data.map(i=>`<tr><td><strong>${safe(i.invoice_no)}</strong></td><td>${safe(i.time_str)}</td><td>${safe(i.items_summary)}</td><td>${money(i.total)}</td><td>${safe(i.cashier)}</td><td>${can(['مدير عام'])?`<button class="btn btn-danger btn-small" onclick="deleteInvoice(${Number(i.id)})">إلغاء الفاتورة</button>`:'—'}</td></tr>`).join('')||'<tr><td colspan="6" class="empty">لا توجد فواتير مسجلة</td></tr>';$('sales-table').innerHTML=rows;$('recent-sales').innerHTML=data.slice(0,5).map(i=>`<tr><td>${safe(i.invoice_no)}</td><td>${safe(i.time_str)}</td><td>${safe(i.items_summary)}</td><td>${money(i.total)}</td><td>${safe(i.cashier)}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">لا توجد مبيعات بعد</td></tr>'}catch(e){toast(e.message,'error')}}
async function deleteInvoice(id){if(!confirm('هل تريد إلغاء الفاتورة؟ سيؤثر ذلك على التقارير.'))return;try{await api('delete_invoice',fd({id}));loadSales();loadDashboard();toast('تم إلغاء الفاتورة')}catch(e){toast(e.message,'error')}}
$('refresh-sales').onclick=loadSales;
$('expense-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('add_expense',fd({title:$('expense-title').value.trim(),amount:$('expense-amount').value}));$('expense-form').reset();await loadExpenses();loadDashboard();toast('تم حفظ المصروف')}catch(err){toast(err.message,'error')}});
async function loadExpenses(){if(!can(['مدير عام','محاسب']))return;try{const data=await api('get_expenses');$('expenses-table').innerHTML=data.map((x,i)=>`<tr><td>${i+1}</td><td>${safe(x.title)}</td><td>${money(x.amount)}</td><td>${safe(x.time_str)}</td><td>${safe(x.cashier||'—')}</td><td>${can(['مدير عام'])?`<button class="btn btn-danger btn-small" onclick="deleteExpense(${Number(x.id)})">حذف</button>`:'—'}</td></tr>`).join('')||'<tr><td colspan="6" class="empty">لا توجد مصروفات مسجلة</td></tr>'}catch(e){toast(e.message,'error')}}
async function deleteExpense(id){if(!confirm('هل تريد حذف هذا المصروف؟'))return;try{await api('delete_expense',fd({id}));loadExpenses();loadDashboard();toast('تم حذف المصروف')}catch(e){toast(e.message,'error')}}
async function loadDashboard(){if(!can(['مدير عام','محاسب']))return;try{const d=await api('get_summary',fd({period:'day'}));$('dash-sales').textContent=money(d.sales);$('dash-count').textContent=d.invoice_count;$('dash-expenses').textContent=money(d.expenses);$('dash-net').textContent=money(d.net);loadSales()}catch(e){toast(e.message,'error')}}
async function runReport(){if(!can(['مدير عام','محاسب']))return;try{const d=await api('get_summary',fd({period:$('report-period').value}));$('report-sales').textContent=money(d.sales);$('report-count').textContent=d.invoice_count;$('report-expenses').textContent=money(d.expenses);$('report-net').textContent=money(d.net)}catch(e){toast(e.message,'error')}}
$('run-report').onclick=runReport;$('refresh-dashboard').onclick=loadDashboard;
function updateClock(){$('clock').textContent=new Date().toLocaleString('ar-SD',{dateStyle:'medium',timeStyle:'short'})}updateClock();setInterval(updateClock,30000);
(async()=>{try{const s=await api('session');if(s.logged_in){window.currentUserId=null;loginUI(s.user,s.role)}}catch(e){} })();
</script>
</body>
</html>
