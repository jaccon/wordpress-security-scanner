<?php
/*
Plugin Name: Security Scanner
Description: Plugin leve para identificar ameaças de segurança no WordPress.
Version: 1.0
Author: @Jaccon
*/

// Adiciona um submenu à seção Ferramentas do menu do WordPress
add_action('admin_menu', 'security_scanner_menu');

function security_scanner_menu() {
    add_submenu_page(
        'tools.php',
        'Security Scanner',
        'Security Scanner',
        'manage_options',
        'security-scanner',
        'security_scanner_page'
    );
}

// Função para renderizar a página do scanner de segurança
function security_scanner_page() {
    ?>
    <div class="wrap">
        <h1>Security Scanner</h1>

        <div class="plugin-description">
            <p style="background: #fff; padding: 20px; border: 1px #ccc solid; margin-bottom: 30px;">
            Este plugin verifica todos os arquivos PHP em seu diretório WordPress em busca de ameaças de segurança, como eval(), base64_decode(), mysql_query(), entre outros. 
            Ele também verifica os arquivos na pasta wp-content/uploads. Após a execução, você pode ver os resultados e visualizar qualquer arquivo suspeito em modo de leitura.
            <br/><br/> by <a href="https://www.jaccon.com.br/wordpress-security-scanner" target="_blank"> @Jaccon </a>
          </p>
        </div>

        <form method="post" action="">
            <input type="hidden" name="security_scanner_nonce" value="<?php echo wp_create_nonce('security-scanner-nonce'); ?>">
            <input type="submit" class="button button-primary" value="Executar Scanner">
        </form>
        <?php
        // Verifica se o formulário foi enviado
        if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['security_scanner_nonce'])) {
            // Verifica o nonce
            if (!wp_verify_nonce($_POST['security_scanner_nonce'], 'security-scanner-nonce')) {
                wp_die('Erro de segurança');
            }
            
            // Executa o scanner de segurança
            $results = run_security_scan();

            // Exibe os resultados do scanner
            echo '<h2>Resultados do Scanner:</h2>';
            echo '<table class="wp-list-table widefat fixed striped">';
            echo '<thead><tr><th>Filename</th><th>Path</th><th>Tipo</th><th> Atualizado em: </th><th>Ver Arquivo</th></tr></thead>';
            echo '<tbody>';
            foreach ($results as $result) {
                echo '<tr>';
                echo '<td>' . esc_html($result['filename']) . '</td>';
                echo '<td>' . esc_html($result['path']) . '</td>';
                echo '<td>' . esc_html($result['type']) . '</td>';
                echo '<td>' . date('Y-m-d H:i:s', filemtime($result['path'] . '/' . $result['filename'])) . '</td>';
                echo '<td><a href="' . admin_url('admin.php?page=view_file&file=' . urlencode($result['path'] . '/' . $result['filename'])) . '" target="_blank">Ver Arquivo</a></td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
        }
        ?>
    </div>
    <?php
}

// Página para visualizar arquivos em modo de leitura
add_action('admin_menu', 'view_file_page');

function view_file_page() {
    add_submenu_page(
        null,
        'View File',
        'View File',
        'manage_options',
        'view_file',
        'view_file_content'
    );
}

function view_file_content() {
    $file = isset($_GET['file']) ? urldecode($_GET['file']) : '';
    if (empty($file) || !file_exists($file)) {
        echo '<div class="wrap"><h2>Arquivo não encontrado</h2></div>';
        return;
    }

    $file_content = file_get_contents($file);
    ?>
    <div class="wrap">
        <h1>Visualizar Arquivo</h1>
        <h2><?php echo basename($file); ?></h2>
        <pre><?php echo htmlspecialchars($file_content); ?></pre>
    </div>
    <?php
}

// Função para executar o scanner de segurança
function run_security_scan() {
    $results = array();

    // Diretórios de arquivos principais (core) do WordPress
    $core_directories = array(
        ABSPATH . 'wp-admin',
        ABSPATH . 'wp-includes'
    );

    // Verifica arquivos no diretório do WordPress
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ABSPATH));
    foreach ($files as $file) {
        // Ignora diretórios
        if ($file->isDir()) {
            continue;
        }

        // Verifica o conteúdo do arquivo
        $content = file_get_contents($file->getPathname());

        // Verifica se há ameaças
        if (preg_match('/eval\s*\(/', $content) ||                 // PHP eval()
            preg_match('/base64_decode\s*\(/', $content) ||       // base64_decode()
            preg_match('/base64_encode\s*\(/', $content) ||       // base64_encode()
            preg_match('/mysql_query\s*\(/', $content) ||         // SQL Injection (mysql_query())
            preg_match('/mysqli_query\s*\(/', $content) ||        // SQL Injection (mysqli_query())
            preg_match('/\$wpdb->query\s*\(/', $content) ||       // SQL Injection ($wpdb->query())
            preg_match('/scandir\s*\(/', $content) ||             // Listar diretórios (scandir())
            preg_match('/readdir\s*\(/', $content) ||             // Listar diretórios (readdir())
            preg_match('/opendir\s*\(/', $content)) {             // Listar diretórios (opendir())

            // Verifica se o arquivo pertence ao core do WordPress ou a um plugin
            $type = is_core_file($file->getPath(), $core_directories) ? 'Core' : 'Plugin';

            $results[] = array(
                'filename' => $file->getFilename(),
                'path' => $file->getPath(),
                'type' => $type,
            );
        }
    }

    // Verifica arquivos na pasta wp-content/uploads
    $uploads_directory = ABSPATH . 'wp-content/uploads';
    if (is_dir($uploads_directory)) {
        $uploads_files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($uploads_directory));
        foreach ($uploads_files as $file) {
            // Ignora diretórios
            if ($file->isDir()) {
                continue;
            }

            // Verifica se o arquivo é PHP
            if (pathinfo($file->getFilename(), PATHINFO_EXTENSION) === 'php') {
                $results[] = array(
                    'filename' => $file->getFilename(),
                    'path' => $file->getPath(),
                    'type' => 'Uploads',
                );
            }
        }
    }

    return $results;
}

// Função para verificar se um arquivo pertence ao core do WordPress ou a um plugin
function is_core_file($file_path, $core_directories) {
    foreach ($core_directories as $directory) {
        if (strpos($file_path, $directory) !== false) {
            return true;
        }
    }
    return false;
}

// Adicionar link na tela de instalação do plugin
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'security_scanner_plugin_action_links');

function security_scanner_plugin_action_links($links) {
    $settings_link = '<a href="' . admin_url('tools.php?page=security-scanner') . '">Configurações</a>';
    array_unshift($links, $settings_link);
    return $links;
}
