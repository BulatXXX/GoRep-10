# Практическая работа #10
## JWT-аутентификация: создание и проверка токенов. Middleware для авторизации
## Саттаров Булат Рамилевич ЭФМО-01-25

--- 
## Описание
В работе реализована система аутентификации и авторизации на основе JWT-токенов:
-	/login — выдача пары токенов access + refresh
-	/refresh — обновление токенов с автоматической ревокацией старого refresh
-	/me — получение данных текущего пользователя	
- /admin/stats — доступно только администратору	
- /users/{id} — ABAC: пользователь может получить только свои данные, администратор — данные любого пользователя

Используются middleware:
-	AuthN — проверка подписи и декодирование токена
-	AuthZ — проверка ролей (RBAC)
-	Error — преобразование ошибок в единый JSON-формат
-	Logging — логирование запроса (метод, путь, статус, время обработки)
-	Rate limit — ограничение количества попыток логина

## Команды запуска и переменные окружения
Запуск 
```
go run ./...
```
Переменные 
- APP_PORT – порт
- JWT_ACCESS_TTL – время жизни access 
- JWT_REFRESH_TTL – время жизни refresh 
- JWT_ACTIVE_KID – какой ключ использовать


## Скриншоты
### Логин
![img.png](docs/screenshots/img.png)
### Запрос себя /me
![img_1.png](docs/screenshots/img_1.png)
### /stats от админа и юзера
![img_2.png](docs/screenshots/img_2.png)
### ABAC запрос данных пользователя по id
#### От роли user только себя (запросив другого 403)
![img_3.png](docs/screenshots/img_3.png)
#### От роли admin всех
![img_4.png](docs/screenshots/img_4.png)
#### Refresh
![img_5.png](docs/screenshots/img_5.png)

## Доп задания
### RS256
#### Измененный конфиг
![img_6.png](docs/screenshots/img_6.png)
![img_7.png](docs/screenshots/img_7.png)
#### Генерация ключей
![img_8.png](docs/screenshots/img_8.png)
#### Вызов в роутере
![img_9.png](docs/screenshots/img_9.png)

### Rate limit
![img_10.png](docs/screenshots/img_10.png)

### Logging через logging.go
![img_11.png](docs/screenshots/img_11.png)

### Единый формат ошибок через middleware errors.go
![img_12.png](docs/screenshots/img_12.png)
#### Пример применения
![img_13.png](docs/screenshots/img_13.png)
#### Вывод ошибки
![img_14.png](docs/screenshots/img_14.png)

