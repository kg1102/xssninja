# XSS Ninja

**XSSNinja** é uma ferramenta em Rust para detecção automatizada de vulnerabilidades de Cross-Site Scripting (XSS) em aplicações web. Ela realiza varreduras em URLs fornecidas, testando diversos payloads em busca de possíveis vulnerabilidades.

## Sumário

- [Características](#características)
- [Instalação](#instalação)
- [Uso](#uso)
- [Opções de Linha de Comando](#opções-de-linha-de-comando)
- [Como Funciona](#como-funciona)
- [Contribuição](#contribuição)
- [Licença](#licença)

## Características

- **Alta Concurrência**: Testa múltiplas URLs simultaneamente utilizando recursos assíncronos do Rust.
- **Payloads Diversificados**: Utiliza uma variedade de payloads conhecidos para detecção de XSS.
- **Extração Inteligente de Parâmetros**: Extrai parâmetros de formulários e scripts presentes nas páginas para testes mais abrangentes.
- **Modos GET e POST**: Testa tanto requisições GET quanto POST.
- **Modo Verbose**: Opção para exibir logs detalhados durante a execução.

## Instalação

Certifique-se de ter o Rust instalado em sua máquina. Você pode instalá-lo através do [rustup](https://rustup.rs/).

Clone o repositório e compile o projeto:

```bash
git clone https://github.com/kg1102/xssninja.git
cd xssninja
cargo build --release
```

O binário compilado estará disponível em `target/release/xssninja`.

## Uso

Você pode utilizar o **xssninja** fornecendo uma lista de URLs através de um arquivo ou via entrada padrão (stdin).

### Exemplo com arquivo:

```bash
./xssninja -f urls.txt
```

### Exemplo com entrada padrão:

```bash
cat urls.txt | ./xssninja
```

### Especificando o nível de concorrência:

```bash
./xssninja -f urls.txt -c 100
```

### Ativando o modo verboso:

```bash
./xssninja -f urls.txt -v
```

## Opções de Linha de Comando

```
USAGE:
    xssninja [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Activates verbose mode

OPTIONS:
    -c, --concurrency <concurrency>    Sets the level of concurrency [default: 200]
    -f, --file <file>                  Path to the file containing URLs
```

## Como Funciona

1. **Leitura de URLs**: A ferramenta lê as URLs a serem testadas de um arquivo ou da entrada padrão.

2. **Download da Wordlist**: Baixa uma wordlist de parâmetros para aumentar a cobertura dos testes.

3. **Varredura de XSS**: Para cada URL:
   - **Análise Inicial**: Faz uma requisição inicial para obter o corpo da resposta.
   - **Extração de Parâmetros**: Extrai nomes de parâmetros de inputs, variáveis JavaScript e URLs presentes no corpo da resposta.
   - **Teste de Payloads**:
     - **Parâmetros Existentes**: Testa payloads nos parâmetros já presentes na URL.
     - **Parâmetros Extraídos**: Testa payloads nos parâmetros extraídos do corpo da resposta.
     - **Parâmetros da Wordlist**: Testa payloads utilizando parâmetros da wordlist externa.
   - **Detecção de XSS**: Verifica se os payloads injetados aparecem na resposta, indicando uma possível vulnerabilidade.

4. **Resultados**: Exibe os resultados encontrados, destacando vulnerabilidades confirmadas e potenciais.

## Exemplo de Saída

```
XSS NINJA - Starting scan...
XSS FOUND (GET): http://exemplo.com/?search=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E
```

- **XSS FOUND**: Vulnerabilidade confirmada.
- **POSSIBLE XSS**: Indica que o payload pode estar presente em um contexto que permite exploração.
- **Sanitzed Payload** (Verbose Mode): O payload foi filtrado pelo servidor.
- **Not Vulnerable** (Verbose Mode): Nenhuma vulnerabilidade detectada com os payloads testados.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e pull requests.

Para configurar o ambiente de desenvolvimento:

1. Clone o repositório.
2. Crie uma nova branch para sua feature ou correção.
3. Faça suas alterações e commit.
4. Abra um pull request descrevendo suas alterações.

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](https://github.com/kg1102/xssninja/blob/master/LICENSE) para mais detalhes.

---

**Aviso Legal**: Esta ferramenta foi desenvolvida com o propósito educativo e de auxiliar em testes de segurança autorizados. O uso indevido pode ser ilegal e é de responsabilidade exclusiva do usuário. Sempre obtenha permissão antes de realizar testes em sistemas que não são de sua propriedade.