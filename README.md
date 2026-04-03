# Net Inventory Scanner

Scanner de rede em C++ no estilo "mini nmap", mas orientado a inventario defensivo.

## O que ele faz

- Descobre hosts ativos por tentativas TCP em portas conhecidas
- Varre um host ou faixa CIDR IPv4
- Usa pool de threads, rate limiting e retry configuravel
- Lista portas abertas por host
- Tenta capturar banners simples de servicos TCP
- Faz reverse DNS dos hosts ativos
- Exporta em formato legivel, JSON, JSONL ou CSV
- Oferece perfis de portas prontos: `common`, `web`, `infra`, `windows`, `database`

## Limites de seguranca

- Aceita apenas `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12` e `192.168.0.0/16`
- Limita a faixa em ate `4096` hosts
- Nao implementa fingerprinting, spoofing, evasao, SYN scan bruto ou tecnicas furtivas
- O discovery e o scan usam apenas conexoes TCP normais

## Build

### g++ no Windows (MinGW)

```powershell
g++ -std=c++17 -O2 -Wall -Wextra -pedantic .\src\main.cpp -lws2_32 -o .\net_inventory_scanner.exe
```

### CMake

```powershell
cmake -S . -B build
cmake --build build
```

## Uso

```powershell
.\net_inventory_scanner.exe --target 192.168.0.0/24
.\net_inventory_scanner.exe --target 192.168.0.0/24 --profile web --format json
.\net_inventory_scanner.exe --target 10.0.0.15 --ports 22,80,443,8080 --retries 2 --rate-limit 100
.\net_inventory_scanner.exe --target 127.0.0.1 --profile database --no-dns --csv
.\net_inventory_scanner.exe --target 192.168.1.0/24 --verbose --no-banners
```

## Parametros principais

- `--target`: host IPv4 ou faixa CIDR
- `--ports`: lista ou ranges, como `22,80,443,8000-8010`
- `--profile`: perfis de portas separados por virgula
- `--timeout-ms`: timeout por conexao
- `--threads`: quantidade de workers
- `--retries`: numero de retries por porta
- `--rate-limit`: maximo aproximado de tentativas por segundo
- `--format`: `human`, `json`, `jsonl` ou `csv`
- `--verbose`: logs de progresso no `stderr`
- `--no-discovery`: pula a etapa de host discovery
- `--no-dns`: desliga reverse DNS
- `--no-banners`: desliga captura de banner

## Exemplo de saida humana

```text
Target: 127.0.0.1
Formato: human
Hosts enumerados: 1
Hosts ativos: 1
Hosts escaneados: 1
Portas agendadas: 6
Tentativas de conexao: 12
Portas abertas: 2
Banners capturados: 1
Tempo discovery: 5 ms
Tempo scan: 8 ms
Tempo reverse DNS: 0 ms
Tempo total: 13 ms

127.0.0.1 (localhost) [ativo via 80]
  80/tcp -> HTTP/1.0 200 OK
  443/tcp -> tls-service-open
```
