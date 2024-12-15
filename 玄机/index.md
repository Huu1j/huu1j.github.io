# 玄机应急响应


<!--more-->

# 玄机应急响应

## 第一章 应急响应-webshell查杀

### 知识点

#### 常用查shell命令

xargs 可以将管道或标准输入数据转换成命令行参数，也能够从文件的输出中读取数据，通常和管道符一起使用

```
find /  -name "*.jsp" | xargs grep "exec(" 
find /  -name "*.php" | xargs grep "eval(" 
find /  -name "*.asp" | xargs grep "execute(" 
find /  -name "*.aspx" | xargs grep "eval(" 
```

对于免杀Webshell，可以查看是否使用编码

```
find /  -name "*.php" | xargs grep "base64_decode" 
```

#### 哥斯拉流量特征

##### 弱特征

1.accept字段

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405291103405.png)

2.Cookie 后面有分号

##### 强特征

### 解题过程

#### 找木马

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405291020651.png)

#### 分析流量特征

根据session，以及默认密钥key值3c6e0b8a9c15224a，可以看到是哥斯拉php websehll流量特征，PHP_XOR_RAW 生成的shell

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405291055422.png)

#### 找隐藏木马

./var/www/html/include/Db/.Mysqli.php  因为前面加了.，所以正常ls是看不到这个文件的，所以这就是我们要找的隐藏shell

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405291022500.png)

#### 找免杀木马

find /  -name "*.php" | xargs grep "base64_decode"

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405291023211.png)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405291024861.png)



找黑客ip

```
cut -d- -f 1 access.log.1|uniq -c | sort -rn | head -20
```

找黑客指纹

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405292124959.png)

```
cat access.log.1 | grep "/index.php" | wc -l
```

wc -l 统计行数

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405292127727.png)

```
cat access.log.1 | grep "192.168.200.2 - -"  | wc -l
```

```
grep -w "192.168.200.2" access.log.1 |wc -l
```

-w参数全匹配

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405292128251.png)

```
cat access.log.1 | grep "03/Aug/2023:08:" | awk '{print $1}' | sort -nr| uniq -c
```

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202405292136517.png)

## 第一章 应急响应-Linux日志分析

#### 查找登录爆破失败的ip

```
cat /var/log/auth.log.1 /var/log/auth.log | grep -a "Failed password for root" | awk '{print $11}' | sort | uniq -c | sort -nr | more
```

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202406011702291.png)

#### 查找登录成功的ip

```
cat /var/log/auth.log.1 /var/log/auth.log | grep -a "Accepted " | awk '{print $11}' | sort | uniq -c | sort -nr | more
```

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202406011704252.png)

#### 查找ssh爆破用户字典

```
cat /var/log/auth.log.1 /var/log/auth.log | grep -a "Failed password" | perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}'| uniq -c | sort -nr
```

可以看到登录失败所尝试的用户名user

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202406011720668.png)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202406011718660.png)

#### 查找ssh爆破次数

```
cat /var/log/auth.log.1 /var/log/auth.log | grep -a "Failed password" | awk '{if($11=="192.168.200.2") print $11}'|sort|uniq -c
```

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202406011729766.png)

#### 查找后门用户

```
cat /var/log/auth.log.1 /var/log/auth.log |grep -a "new user"
```

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202406011731225.png)

同时也可以通过查看/etc/passwd文件，排查可疑用户，uid在1-999是无法登录的用户，而test2的uid是1000，且比较靠后

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202406011738994.png)

## 第六章-哥斯拉4.0流量分析

### 1.黑客ip

192.168.31.190对192.168.31.168:8080进行目录扫描

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410161436649.png)

flag{192.168.31.190}

### 2.黑客通过什么漏洞进入服务器(提交cve编号)

往下翻，发现黑客通过put方法上传木马

经过查询，tomcat通过PUT方法任意文件写入(CVE-2017-12615)，tomcat解析到后缀名为`jsp`或者`jspx`的时候会交给`JspServlet`，最后的`/`是因为文件名特性最后不支持`/`默认会去除就可以绕过`JspServlet`文件的解析，所以在hello.jsp后面要加个`/`

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410161457878.png)

flag{CVE-2017-12615}

### 3.黑客上传的木马文件名

ip.src==192.168.31.190&&ip.dst==192.168.31.168

往下翻，发现put方法的hello.jsp,疑似木马，追踪tcp流

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410161457878.png)

可以看到服务器响应码是201，表示请求已经被成功处理，并且创建了新的资源，木马成功植入

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410161500293.png)

flag{hello.jsp}

### 4.黑客上传木马连接密码

追踪tcp流

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410161455332.png)

flag{7f0e6f}

### 5.黑客上传木马解密密钥

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410161455332.png)

flag{1710acba6220f62b}

### 6.黑客连接webshell后执行的第一条命令

ip.src==192.168.31.190&&ip.dst==192.168.31.168&&http.request.uri=="/hello.jsp"

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410162048497.png)



flag{uname -r}

### 7.黑客连接webshell查询当前shell是什么

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410162020060.png)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410162019952.png)

flag{root}

### 8、黑客利用webshell执行命令查询服务器Linux系统发行版本是什么？

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410161554851.png)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410161552453.png)

flag{Debian GNU/Linux 10 (buster)}

### 9、黑客利用webshell执行命令还查询并过滤了什么？（提交整条执行成功的命令）

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410171111435.png)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410162056978.png)

flag{dpkg -l libpam-modules:amd64}

### 10、黑客留下后门的反连的IP和PORT是什么？（IP:PORT)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410162029575.png)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410162030886.png)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410162030886.png)

flag{192.168.31.143:1313}

### 11、黑客通过什么文件留下了后门？

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410171108036.png)





flag{pam_unix.so}

### 12、黑客设置的后门密码是什么？

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410171131863.png)

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410171131756.png)



flag{XJ@123}

### 13、黑客的恶意dnslog服务器地址是什么？

![](https://cdn.jsdelivr.net/gh/Huu1j/Huuj_img@main/img/202410171138556.png)

flag{c0ee2ad2d8.ipv6.xxx.eu.org.}

