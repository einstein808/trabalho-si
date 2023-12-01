# Relatório sobre o Uso da Ferramenta de Inspeção de Código Bearer Scan

## Introdução

No último ano, a segurança de aplicações tornou-se uma prioridade crescente. Ferramentas de inspeção de código desempenham um papel crucial na identificação de vulnerabilidades e na melhoria da integridade do software. Este relatório se concentra na avaliação da ferramenta Bearer Scan, especificamente utilizada para análise de código de segurança em aplicações web.

## Instalação da Ferramenta

A instalação da ferramenta Bearer Scan pode ser realizada com os seguintes passos:

1. **Requisitos de Sistema:** Certifique-se de ter o Node.js instalado na máquina.

2. **Instalação via npm:** Utilize o seguinte comando no terminal:

   ```
   bashCopy code
   npm install -g @bearer/bearer-cli
   ```

3. **Configuração Inicial:** Execute o seguinte comando para configurar a ferramenta:

   ```
   bashCopy code
   bearer init
   ```

A ferramenta está agora pronta para uso após essas etapas.

Eu fiz a instalação através de maquina virtual em ubuntu via terminal

```
sudo apt-get install apt-transport-https
echo "deb [trusted=yes] https://apt.fury.io/bearer/ /" | sudo tee -a /etc/apt/sources.list.d/fury.list
sudo apt-get update
sudo apt-get install bearer
```

Depois clonei repositório Juice Shop
https://github.com/juice-shop/juice-shop

Depois fiz o scan via repositório

``bearer scan juice-shop``



## Utilização da Ferramenta

A Bearer Scan é uma ferramenta abrangente que oferece diversas funcionalidades para identificar vulnerabilidades em aplicações web. Aqui estão algumas das principais funcionalidades:

1. **Análise de Código:** A ferramenta analisa o código em busca de vulnerabilidades conhecidas, como hard-coded secrets, possíveis vulnerabilidades de travessia de caminho e uso perigoso de eval.
2. **Relatório de Segurança:** Após a análise, a ferramenta gera um relatório de segurança detalhado, destacando as vulnerabilidades encontradas, classificadas por gravidade.
3. **Ignorar Resultados:** A Bearer Scan permite ignorar resultados específicos, o que é útil para situações em que a vulnerabilidade é conhecida e aceita.
4. **Suporte a Múltiplas Linguagens:** A ferramenta suporta várias linguagens, incluindo JavaScript e Python, tornando-a versátil para diferentes tipos de projetos.

## Exemplos de Código Analisados

A seguir  estão exemplos específicos de código analisados pela ferramenta de um código feito propositalmente com vulnerabilidades https://github.com/juice-shop/juice-shop, destacando as vulnerabilidades identificadas:

1. **Hard-coded Secrets (Algoritmo CWE-798):**

   - **Ocorrências:** 4

   - **Descrição:** Senhas, chaves de API ou outros segredos foram encontrados diretamente no código-fonte.

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/lib/insecurity.ts
     export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
     ```

2. **Possible Path Traversal Vulnerabilities (CWE-22):**

   - **Ocorrências:** 3

   - **Descrição:** Potencial vulnerabilidade que permite a um invasor acessar diretórios fora do previsto.

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/routes/dataErasure.ts
     const filePath: string = path.resolve(req.body.layout).toLowerCase()
     ```

3. **Dangerous Dynamic HTML Insertion (CWE-79):**

   - **Ocorrências:** 1

   - **Descrição:** Inserção dinâmica de HTML que pode levar a ataques de Cross-Site Scripting (XSS).

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/frontend/src/hacking-instructor/index.ts
     textBox.innerHTML = snarkdown(hint.text)
     ```

4. **Dangerous Use of Eval with User Input (CWE-94, CWE-95):**

   - **Ocorrências:** 2

   - **Descrição:** Avaliação dinâmica de código com entrada do usuário, o que pode levar a vulnerabilidades.

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/routes/b2bOrder.ts
     vm.createContext(sandbox)
     vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
     ```

5. **HTTP Communication with User-Controlled Destination (CWE-918):**

   - **Ocorrências:** 1

   - **Descrição:** Comunicação HTTP com destino controlado pelo usuário, o que pode ser explorado para ataques.

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/routes/profileImageUrlUpload.ts
     const imageRequest = request.get(url)
     ```

6. **Sensitive Data in Logger Messages (CWE-1295, CWE-532):**

   - **Ocorrências:** 2

   - **Descrição:** Dados sensíveis são registrados em mensagens de log, o que pode levar a vazamento de informações.

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/frontend/src/app/faucet/faucet.component.ts
     console.log(balanceBigNumber)
     ```

7. **SQL Injection Vulnerabilities (CWE-89):**

   - **Ocorrências:** 8

   - **Descrição:** Injeção de SQL, uma vulnerabilidade grave que permite a manipulação maliciosa de consultas SQL.

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts
     models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%"+criteria+"%' OR description LIKE '%"+criteria+"%') AND deletedAt IS NULL) ORDER BY name")
     ```

8. **Missing Access Restriction to Directory Listing (CWE-548):**

   - **Ocorrências:** 13

   - **Descrição:** Falta de restrição de acesso a listagens de diretórios, o que pode expor informações sensíveis.

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/data/static/codefixes/accessLogDisclosureChallenge_1_correct.ts
     app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))
     ```

9. **External Control of Filename or Path (CWE-73):**

   - **Ocorrências:** 3

   - **Descrição:** Controle externo de nome de arquivo ou caminho, uma vulnerabilidade que pode ser explorada para acesso não autorizado.

   - Exemplo de Código:

     ```
     typescriptCopy code// File: juice-shop/routes/keyServer.ts
     res.sendFile(path.resolve('encryptionkeys/', file))
     ```

10. **Unrevoked JWT (CWE-525):**

- **Ocorrências:** 2

- **Descrição:** Uso de tokens JWT não revogados, o que pode levar a acessos não autorizados.

- Exemplo de Código:

  ```
  typescriptCopy code// File: juice-shop/lib/insecurity.ts
  export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)
  ```



###  Vulnerabilidades que eu consegui encontrar.

1. **SQL Injection**
   ![Alt Text](https://github.com/einstein808/trabalho-si/blob/main/sqlinjection.gif)

2.**Missing Access Restriction to Directory Listing (CWE-548):**
![alt text](.\ftp.gif)

3. **Missing Access Restriction to Directory Listing (CWE-548):**

   ![](https://github.com/einstein808/trabalho-si/blob/main/administration.webp))

![](./adm.gif)

## Críticas à Utilização da Ferramenta

Apesar da eficácia da Bearer Scan na identificação de vulnerabilidades, algumas críticas podem ser observadas:

1. **Complexidade de Ignorar Resultados:** Ignorar resultados específicos pode ser complexo, especialmente para equipes menos familiarizadas com a ferramenta.
2. **Limitações na Identificação de Vulnerabilidades Específicas:** Alguns casos podem não ser identificados corretamente, exigindo uma análise manual adicional.

## Perspectivas de Ganho

O uso da ferramenta Bearer Scan pode trazer benefícios significativos para equipes de desenvolvimento:

1. **Aprimoramento da Segurança:** A identificação proativa de vulnerabilidades permite correções antes da implantação, fortalecendo a segurança das aplicações.
2. **Padronização de Boas Práticas:** A ferramenta incentiva a conformidade com boas práticas de segurança, promovendo um código mais robusto desde o início do desenvolvimento.

## Análise Geral e Conclusão

A Bearer Scan é uma ferramenta valiosa para equipes de desenvolvimento preocupadas com a segurança de suas aplicações. Apesar de algumas críticas, seus benefícios superam as limitações. A capacidade de identificar uma ampla variedade de vulnerabilidades, juntamente com a flexibilidade de suporte a várias linguagens, fazem dela uma escolha sólida para aprimorar a segurança do código.

Em conclusão, a incorporação da Bearer Scan no processo de desenvolvimento pode contribuir significativamente para a construção de aplicações mais seguras, protegendo contra ameaças potenciais desde as fases iniciais do ciclo de vida do desenvolvimento.
