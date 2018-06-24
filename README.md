#steamBot
经过2个多月的调试开发,终于把steamBot的主要接口都实现了。目前只提供了函数库,通过二次开发便可投入使用,本项目严格遵守Apache License V2
以下为目前已实现的API


- 接受/拒绝/取消/发起交易
- 支持二步验证的登录
- 支持运算二步验证吗
- 获取steamID SessionID
- 获取玩家游戏列表
- 获取API秘钥
- 获取玩家库存

代码放库[有问题戳我BLOG留言,我看得见的OWO],demo已经包含在函数库内
<hr>
使用方法:
<code>
<?php
$steambot = new SteamBot;
$steambot->函数名();
?>
</code>
<hr>
我的测试环境是Apache+PHP5.5n,如果出现empty respone 我只能归结为玄学事件,至今我都没啥头绪
<strong>[2018/06/24]
</strong>最近已经恢复了steam社区的访问,所以机器人恢复至可用状态,并且加入了二步验证的计算以及,把函数库转为了面对象
<hr>
邮箱:gz_7gugu@outlook.com

Blog Link:www.7gugu.com