/*
	Launch_LocalSystem - позволяет запустить любую программу от имени "СИСТЕМА".
    Программа принимает один аргумент - относительный или полный путь до запускаемой программы.

	Данная программа является свободным программным обеспечением, распространяющимся по лицензии MIT.
	Копия лицензии: https://opensource.org/licenses/MIT

	Copyright (c) 2024 Otto
	Автор: Otto
	Версия: 29.07.24
	GitHub страница:  https://github.com/Otto17/Launch_LocalSystem
	GitFlic страница: https://gitflic.ru/project/otto/launch_localsystem

	г. Омск 2024
*/


#include <windows.h>    // Библиотека, которая предоставляет доступ к API Windows
#include <stdio.h>      // Библиотека для определения функций и работы с потоками ввода/вывода
#include <tlhelp32.h>   // Библиотека предоставляет функции для работы с системной информацией о процессах и потоках в OS Windows
#include <locale.h>     // Библиотека для работы с локалью в программе


//Функция формирования ошибки
void PrintError(const char* msg) {
    DWORD eNum;
    char* lpMsgBuf;
    char* lpDisplayBuf;

    eNum = GetLastError();  // Получаем код последней ошибки, произошедшей в ходе выполнения программы

    //Формируем текстовое сообщение об ошибке на основе кода ошибки "eNum"
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf, 0, NULL);

    //Выделяем память под строку "lpDisplayBuf". 
    lpDisplayBuf = (char*)LocalAlloc(LMEM_ZEROINIT, strlen(msg) + strlen(lpMsgBuf) + 40);   // Выделяемый размер равен сумме длины входного сообщения, длины сообщения об ошибке и 40 дополнительных символов для форматирования
    sprintf(lpDisplayBuf, "%s произошел сбой с ошибкой %d: %s", msg, eNum, lpMsgBuf);       // Формируем строку

    printf("%s\n", lpDisplayBuf);   // Выводим сформированное сообщение в командную строку

    //Освобождаем память
    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}


//Функция получения повышенных привилегий
BOOL EnablePrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) { // "hToken" - дескриптор токена доступа; "lpszPrivilege" - строка, содержащая имя привилегии, которую нужно изменить; "bEnablePrivilege" - логическое значение, указывающее, нужно ли включить или выключить привилегию
    TOKEN_PRIVILEGES tp;
    LUID luid;

    //Получаем "LUID" для указанной привилегии
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {    // "NULL" указывает, что запрос осуществляется для локальной системы; "lpszPrivilege" - переданное имя
        PrintError("LookupPrivilegeValue"); // Выводим ошибку
        return FALSE;                       // Неудача
    }

    tp.PrivilegeCount = 1;                                                          // Устанавливаем кол-во привилегий
    tp.Privileges[0].Luid = luid;                                                   // Присваиваем значение "LUID" для первой привилегии (которая мы получили ранее) в массив "Privileges" структуры "tp".
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;    // Устанавливаем атрибут привилегии: если "bEnablePrivilege" равно "TRUE", привилегия будет включена, иначе нет

    //Вызываем функцию "AdjustTokenPrivileges" для изменения привилегий токена "hToken"
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {  // Если вызов не удаётся
        PrintError("AdjustTokenPrivileges");    // Выводим ошибку
        return FALSE;
    }

    //Проверяем, произошла ли последняя ошибка при попытке изменения привилегий
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { // Если код ошибки равен "ERROR_NOT_ALL_ASSIGNED", это означает, что токен не имеет всех указанных привилегий
        printf("Токен не обладает указанными привилегиями.\n");
        return FALSE;
    }

    return TRUE;    // Если все прошло успешно, функция возвращает "TRUE", указывая на успешное включение или выключение привилегии
}


//Метод получения PID процесса
DWORD GetWinlogonPid() {
    DWORD winlogonPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Создаём снимок всех текущих процессов в системе. Возвращается дескриптор "hSnapshot"
    if (hSnapshot == INVALID_HANDLE_VALUE) {    // Если ошибка при получении дескриптора
        PrintError("CreateToolhelp32Snapshot"); // Выводим ошибку
        return 0;
    }

    PROCESSENTRY32 pe;                  // Переменная для хранения информации о процессе
    pe.dwSize = sizeof(PROCESSENTRY32); // Устанавливаем размер структуры

    //Выполняем первую попытку получить информацию о процессе из снимка
    if (Process32First(hSnapshot, &pe)) {   // Если функция успешно выполняется, возвращается значение, отличное от 0
        //Цикл "do" будет продолжаться до тех пор, пока будут оставаться процессы для обхода
        do {
            if (_stricmp(pe.szExeFile, "winlogon.exe") == 0) {  // Проверяем, соответствует ли имя исполняемого файла текущего процесса "winlogon.exe"
                winlogonPid = pe.th32ProcessID;                 // Если имя соответствует, то идентификатор процесса "th32ProcessID" для найденного процесса сохраняется в переменной "winlogonPid"
                break;
            }
        }
        //Оператор "while" продолжает цикл до тех пор, пока функция "Process32Next" возвращает истинное значение (идет следующий процесс в списке)
        while (Process32Next(hSnapshot, &pe));
    } else {
        PrintError("Process32First");   // Выводим ошибку
    }

    CloseHandle(hSnapshot); // Закрываем дескриптор "hSnapshot", освобождаем память
    return winlogonPid;     // Возвращаем значение переменной "winlogonPid", которое может быть 0 (если процесс не найден) или идентификатор найденного процесса "winlogon.exe"
}


//Функция установки цвета в командной строке Windows
void setConsoleTextColor(WORD color) {                  // Функция принимает 16-битное число цвета
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);  // Получаем дескриптор консоли
    SetConsoleTextAttribute(hConsole, color);           // Устанавливаем цвет в консоли
}


int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "ru_RU.UTF-8"); // Установка локали для корректного отображения текста на Русском языке

    // Если получили менее 1 аргумента (нулевой аргумент это сам исполняемый файл Launch_LocalSystem)
    if (argc < 2) {
    //СПРАВКА
        setConsoleTextColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);    // Ярко белый цвет
        printf("Launch_LocalSystem - позволяет запустить любую программу от имени \"СИСТЕМА\".\n");
        printf("Программа принимает один аргумент - относительный или полный путь до запускаемой программы.\n\n");

        setConsoleTextColor(FOREGROUND_RED | FOREGROUND_INTENSITY);     // Ярко красный цвет
        printf("Использование: Launch_LocalSystem.exe <Путь к программе>\n\n");

        setConsoleTextColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);   // Ярко жёлтый цвет
        printf("Автор Otto, г.Омск 2024\n");
        printf("GitHub страница:  https://github.com/Otto17/Launch_LocalSystem\n");
        printf("GitFlic страница: https://gitflic.ru/project/otto/launch_localsystem\n");

        setConsoleTextColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // Сбрасываем цвет на стандартный
        return 1;
    }

    //Объявляем переменные
    HANDLE hToken;
    HANDLE hWinlogonToken = NULL;
    HANDLE hDupToken;
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    DWORD winlogonPid = GetWinlogonPid();

    //Проверяем, нашли ли идентификатор процесса "winlogon.exe" или нет
    if (winlogonPid == 0) {
        printf("Не удалось найти процесс - \"winlogon.exe\".\n");
        return 1;
    }

    ZeroMemory(&si, sizeof(STARTUPINFO));           // Заполняем область памяти нулями (инициализируем структуру "si")
    si.cb = sizeof(STARTUPINFO);                    // Устанавливаем размер структуры для "si"
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));   // Заполняем область памяти нулями (инициализируем структуру "pi")

    //Пытаемся открыть токен доступа текущего процесса с запросом прав "TOKEN_ADJUST_PRIVILEGES" (для изменения привилегий) и "TOKEN_QUERY" (для запроса информации о токене)
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {   // Установка привилегии "SeDebugPrivilege"
        PrintError("OpenProcessToken"); // Выводим ошибку
        return 1;
    }

    //Проверка успешности активаций привилегии "SeDebugPrivilege" для текущего токена
    if (!EnablePrivilege(hToken, SE_DEBUG_NAME, TRUE)) {    // Если вернула false, это означает, что привилегия не была активирована
        CloseHandle(hToken);                                // Закрываем дескриптор и освобождаем память
        return 1;
    }

    //Открываем токен для процесса "winlogon", используя его идентификатор "winlogonPid"
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (hProcess == NULL) {         // Если процесс открыт не успешно
        PrintError("OpenProcess");  // Выводим ошибку
        CloseHandle(hToken);        // Закрываем дескриптор и освобождаем память
        return 1;
    }

    //Пытается открыть токен доступа для процесса "winlogon", запрашивая право на дублирование токена
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hWinlogonToken)) {
        PrintError("OpenProcessToken"); // Выводим ошибку
        CloseHandle(hProcess);          // Закрываем дескриптор процесса и освобождаем память
        CloseHandle(hToken);            // Закрываем дескриптор и освобождаем память
        return 1;
    }

    //Пытается дублировать токен "hWinlogonToken", задавая права "MAXIMUM_ALLOWED", используя режим "SecurityImpersonation" с типом токена "TokenPrimary"
    if (!DuplicateTokenEx(hWinlogonToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        PrintError("DuplicateTokenEx"); // Выводим ошибку
        CloseHandle(hWinlogonToken);    // Закрываем дескриптор токена
        CloseHandle(hProcess);          // Закрываем дескриптор процесса и освобождаем память
        CloseHandle(hToken);            // Закрываем дескриптор и освобождаем память
        return 1;
    }

    //Создаём новый процесс с дублированным токеном
    if (!CreateProcessAsUser(             // Если вернулся результат отличный от нуля, это значит, что процесс не был успешно создан.
            hDupToken,                    // Токен
            NULL,                         // Название приложения
            argv[1],                      // Командная строка
            NULL,                         // Атрибуты процесса
            NULL,                         // Атрибуты потока
            FALSE,                        // Наследование дескрипторов
            0,                            // Флаги создания
            NULL,                         // Окружающая среда
            NULL,                         // Текущий каталог
            &si,                          // Информация о запуске
            &pi)) {                       // Информация о процессе

        PrintError("CreateProcessAsUser");  // Выводим ошибку
        CloseHandle(hDupToken);             // Закрываем дескриптора дублированного токена
        CloseHandle(hWinlogonToken);        // Закрываем дескриптор токена
        CloseHandle(hProcess);              // Закрываем дескриптор процесса и освобождаем память
        CloseHandle(hToken);                // Закрываем дескриптор и освобождаем память
        return 1;
    }

    //Чистим память
    CloseHandle(pi.hProcess);       // Закрываем дескриптора процесса, возвращенного функцией "CreateProcessAsUser"
    CloseHandle(pi.hThread);        // Закрываем дескриптора потока, возвращенного функцией "CreateProcessAsUser"
    CloseHandle(hDupToken);         // Закрываем дескриптора дублированного токена
    CloseHandle(hWinlogonToken);    // Закрываем дескриптор токена
    CloseHandle(hProcess);          // Закрываем дескриптор процесса и освобождаем память
    CloseHandle(hToken);            // Закрываем дескриптор и освобождаем память

    printf("Процесс успешно запущен от имени \"СИСТЕМА\".\n");
    return 0;
}
