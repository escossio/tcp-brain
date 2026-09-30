# Marco de Engenharia — TCP Brain reativado e validado em produção

Data: 30 de setembro de 2026

## Resumo

O TCP Brain voltou a operar como uma camada ativa de observabilidade de rede e,
na primeira investigação real após sua reativação, localizou a causa raiz de
uma falha que impedia o Transport do Attention Router de alcançar o Browser
via CDP em `10.77.10.2:9223`.

A investigação saiu de um timeout aparentemente genérico e chegou até um
defeito específico no caminho de transmissão do namespace: o SYN TCP saía
fisicamente pela VLAN 211 com checksum inválido por causa de offloads de TX no
stack `macvlan -> VLAN -> r8169`.

A correção desabilitou TX checksum, TSO e GSO apenas no `eth0` do namespace
`andy-transport`, persistiu essa decisão no script de criação do namespace e
restabeleceu o CDP sem reiniciar o Browser, sem QR e sem novo pareamento.
## Contexto

O TCP Brain não nasceu nesta investigação. O backend histórico, o banco de
padrões e a interface já existiam, mas o pipeline de detecção estava parado
desde 1º de maio de 2026.

A retomada foi deliberadamente incremental. O backend antigo não foi
substituído. Em vez disso, foi criada uma nova camada passiva de captura e uma
nova camada de análise de fluxo, isoladas do banco histórico e do caminho de IA.

A captura física foi montada assim:

`MikroTik ether2 -> mirror -> ether5 -> AGT enp3s0`

A `enp3s0` passou a operar como interface dedicada de captura, sem IPv4,
IPv6, rota, bridge ou VLAN filha.
## O problema observado

O Transport estava ativo, mas não conseguia alcançar o endpoint CDP do Browser:

`10.77.10.10 -> 10.77.10.2:9223`

O Browser estava funcional e o CDP respondia localmente dentro de seu
namespace. O problema estava, portanto, no caminho entre Transport e Browser.

O Flow Analyzer observou uma tentativa típica com:

- 2 SYN enviados;
- 1 retry;
- 0 SYN/ACK;
- 0 RST;
- estado final `HANDSHAKE_INCOMPLETE`.

A mesma tentativa teve presença física confirmada pelo mirror da MikroTik.
## A nova feature

O novo capture plane lê somente uma janela limitada de cabeçalhos e publica
metadados L2/L3/L4 estruturados. Ele não persiste payload bruto.

Sobre esse stream foi criado o Flow Analyzer, que:

- agrupa pacotes por fluxo;
- acompanha SYN, SYN/ACK, ACK, RST e FIN;
- diferencia cópia de SPAN de retransmissão real;
- conta retries;
- correlaciona VLANs e pontos de observação;
- emite eventos estruturados e linguagem natural;
- não chama IA para diagnosticar o fluxo.

Uma segunda camada passou a localizar o salto inter-VLAN, correlacionando o
mesmo SYN antes e depois do roteamento pela MikroTik.
## Evidência de localização do salto

Para o caso Transport -> Browser, o sistema comprovou:

1. SYN presente na VLAN 211 no trunk do AGT.
2. O mesmo ingresso confirmado pelo mirror físico da ether2.
3. Nenhuma emissão correspondente observada na VLAN 210.
4. Nenhum SYN/ACK retornado.

O evento produzido foi `INTER_VLAN_EGRESS_MISSING`.

Como controle independente, foi criada temporariamente uma regra RAW
`passthrough` com match exato para o TCP problemático. Durante a tentativa,
o contador ficou em 0.

Um controle ICMP da mesma origem para o gateway da VLAN 211 incrementou 3/3.
As duas regras temporárias foram removidas imediatamente após a medição.
## Causa raiz

A evidência física mostrou que o SYN TCP chegava ao fio com checksum inválido.

Antes da correção, o cálculo de one's complement do segmento TCP não fechava
em `0xffff`.

Como controle, tráfego funcional Worker VLAN 213 -> PostgreSQL VLAN 215,
capturado pelo mesmo mirror, apresentava checksum TCP válido.

No namespace `andy-transport`, a interface `eth0` anunciava:

- TX checksumming: ON;
- TSO: ON;
- GSO: ON.

Esse conjunto de offloads, no stack `macvlan -> VLAN -> enp1s0/r8169`, não
estava finalizando corretamente o checksum antes da transmissão física.
## Correção

Foi aplicado no `eth0` do namespace Transport:

`ethtool -K eth0 tx off tso off gso off`

A configuração foi persistida em:

`/usr/local/sbin/andy-transport-netns`

Após a alteração:

- o SYN apareceu no mirror com checksum válido;
- `10.77.10.2:9223` ficou imediatamente acessível;
- o contador de encaminhamentos inter-VLAN correlacionados voltou a subir;
- o Transport foi reiniciado isoladamente;
- o Browser não foi reiniciado;
- não houve QR nem novo pareamento;
- `/ready` voltou HTTP 200 em aproximadamente 3 segundos.
## Estado após a correção

O Transport passou a reportar:

- `service_state=ready`;
- `browser_debug_reachable=true`;
- `wwebjs_connected=true`;
- `owner_identity_verification=MATCH`;
- `owner_command_authority_ready=true`;
- `client_state=CONNECTED`;
- `ready=true`.

O Browser permaneceu na mesma sessão e no mesmo processo durante a correção.

## Por que este é um marco

A importância desta passada não está apenas no bug corrigido.

Pela primeira vez, o TCP Brain foi usado como instrumento operacional para
reduzir uma falha real de ponta a ponta: de timeout, para ausência de SYN/ACK,
para ausência de egress inter-VLAN, para descarte antes do RAW da MikroTik, e
finalmente para checksum TCP inválido no fio.

A arquitetura de observabilidade deixou de ser apenas uma proposta e produziu
uma causa raiz verificável.
## Segurança e limites

O diagnóstico de fluxo foi metadata-only e não utilizou IA.

O capture plane não persiste payload. A voz usada na página pública deste
marco é uma camada separada de apresentação, gerada com Zagan/xAI.

A interface física de captura opera a 100 Mb/s. Isso não é tratado como
degradação por princípio; a condição operacional relevante é perda real.

Durante carga maior, o coletor AF_PACKET em Python registrou drops de socket
mesmo sem RX drops na interface. Esse hardening de buffer/processamento
permanece como trabalho técnico separado e não altera a causa raiz acima.

O sensor de trunk continua sendo uma testemunha temporária de validação. A
arquitetura final deve reduzir dependências de sensores redundantes conforme
as garantias de captura física forem amadurecidas.
