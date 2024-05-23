<?php


namespace vBulletin\Search;

/**
 * В этом коде были исправлены следующие ошибки:
 *
 * 1. **SQL-инъекции**:
 *    - Исправлены потенциальные уязвимости для SQL-инъекций путём использования параметризованных запросов в методах `prepareQuery` и `executeQuery`.
 *
 * 2. **Обработка ошибок**:
 *    - Добавлена обработка ошибок в методе `executeQuery` для улавливания и корректного отображения ошибок выполнения запросов.
 *    - Добавлена обработка ошибок в методе `ensureConnection`, чтобы информировать пользователя о проблемах с подключением к базе данных.
 *
 * 3. **Валидация и экранирование данных**:
 *    - Внедрён класс `RequestValidator`, который обрабатывает и валидирует входящие данные запроса, защищая от XSS-уязвимостей.
 *
 * 4. **Уязвимость XSS **:
 *    - Использование функции `htmlspecialchars` для экранирования пользовательского ввода в методе `process_field` класса `RequestValidator`.
 *
 * 5. **Безопасность файлов**:
 *    - Улучшена проверка на доступность файла для записи в методе `logSearch` класса `Logger`.
 */

class RequestValidator {
    // Метод для валидации полей запроса
    public function validate_fields($request): array {
        foreach ($this->rules as $key => $rule) {
            $request[$key] = $this->process_field($key, $request);
            if (in_array('required', $rule)) {
                if (!array_key_exists($key, $request) || empty($request[$key])) {
                    return [
                        'status' => false,
                        'error' => "нет поля $key"
                    ];
                }
            }
            if (in_array('string', $rule)) {
                if (!is_string($request[$key])) {
                    return [
                        'status' => false,
                        'error' => "Поле $key должно быть строкой"
                    ];
                }
            }
        }
        return ['status' => true, 'request' => $request];
    }

    // Метод для обработки поля запроса (тримминг и экранирование спецсимволов)
    public function process_field($field, $request) {
        if (array_key_exists($field, $request)) {
            return trim(htmlspecialchars($request[$field]));
        } else {
            return null;
        }
    }

    // Правила валидации для полей запроса
    public array $rules = [
        'searchid' => ['string', 'required'],
        'do' => ['string', 'required'],
        'query' => ['string', 'required']
    ];
}

class ConnectionDB {
    // Настройки подключения к базе данных
    private $dns = "mysql:host=127.0.0.1;dbname=vbforum;charset=utf8";
    private $db_user = "forum";
    private $db_password = "123456";

    public $connection;
    public $query;
    public $request;

    public function __construct($request) {
        $this->request = $request;
    }

    public function handle() {
        $connect_result = $this->ensureConnection();
        if ($connect_result['status']) {
            $this->prepareQuery();
            return [
                'status' => true,
                'result' => $this->executeQuery()
            ];
        } else {
            return [
                'status' => false,
                'error' => $connect_result['error']
            ];
        }
    }

    // Метод для установки подключения к базе данных
    public function ensureConnection() {
        try {
            $options = [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            ];
            $conn = new \PDO($this->dns, $this->db_user, $this->db_password, $options);
            $this->connection = $conn;
            return ['status' => true];
        } catch (\PDOException $e) {
            return [
                "status" => false,
                "error" => 'Нет подключения: ' . $e->getMessage()
            ];
        }
    }

    // Метод для подготовки SQL-запроса в зависимости от запроса пользователя
    public function prepareQuery() {
        if (isset($this->request['searchid']) && !empty($this->request['searchid'])) {
            $this->request['do'] = 'showResults';
        } elseif (!empty($this->request['q'])) {
            $this->request['do'] = 'process';
            $this->request['query'] = $this->request['q'];
        }

        if ($this->request['do'] == 'process') {
            // Использование параметризованного запроса для защиты от SQL-инъекций
            $this->query = $this->connection->prepare('SELECT * FROM vb_post WHERE text LIKE ?');
        } elseif ($this->request['do'] == 'showResults') {
            // Использование параметризованного запроса для защиты от SQL-инъекций
            $this->query = $this->connection->prepare('SELECT * FROM vb_searchresult WHERE searchid = ?');
        }
    }

    // Метод для выполнения подготовленного SQL-запроса
    public function executeQuery() {
        try {
            if ($this->request['do'] == 'process') {
                // Выполнение параметризованного запроса
                $this->query->execute(array('%' . $this->request['query'] . '%'));
            } elseif ($this->request['do'] == 'showResults') {
                // Выполнение параметризованного запроса
                $this->query->execute(array($this->request['searchid']));
            }
            // Возврат результатов запроса
            return $this->query->fetchAll();
        } catch (\PDOException $e) {
            // Обработка ошибок выполнения запроса
            return ['status' => false, 'error' => $e->getMessage()];
        }
    }
}

class Search {
    public function doSearch(): void {
        $validator = new RequestValidator();
        // Валидация входящих данных запроса
        $validation_result = $validator->validate_fields($_REQUEST);
        if (!$validation_result['status']) {
            die($validation_result['error']);
        }
        $request = $validation_result['request'];

        // Создание подключения к базе данных и выполнение запроса
        $db_conn = new ConnectionDB($request);
        $result = $db_conn->handle();
        if (!$result['status']) {
            echo $result['error'];
        } else {
            $this->renderSearchResults($result['result']);
        }
    }

    // Метод для отображения результатов поиска
    public function renderSearchResults($result) {
        global $render;

        foreach ($result as $row) {
            // Исключение форума с id 5 из результатов поиска
            if ($row['forumid'] != 5) {
                $render->renderSearchResult($row);
            }
        }
    }
}

class Logger {
    public function logSearch() {
        $filename = '/var/www/search_log.txt';
        $logResults = $_REQUEST['query'] . "\n";
        if (is_writable($filename)) {
            if (!$handle = fopen($filename, 'a+')) {
                echo "не могу открыть ($filename)";
                exit;
            }
            if (fwrite($handle, $logResults) === FALSE) {
                echo "Не могу произвести запись в файл ($filename)";
                exit;
            }
            fclose($handle);
        } else {
            echo "Файл $filename недоступен для записи";
        }
    }
}