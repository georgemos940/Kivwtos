# SOC Ticket Templates

> This page contains standard templates used for opening SOC tickets.  
> Replace the dummy data with actual incident details before sending to a customer.

<hr style="border-top: 3px double #bbb;">

# 📝 SOC Ticket Guidelines 

```
On **--- ---, 2025, --:---:--PM** (UTC+03:00 — Athens) the host with:

* Source IP : **---.---.---.--** 
* Destination IP: **--.---.---.---**
* Windows Computer Name: **----------**
* Events Count: **-------------**
* Firewall Action: **allowed** (**NOT** Blocked)

---


<br>
---

*[ Some References ]*

- [Reference1](https://example.com)
- [Reference2](https://example.com)
- [Reference3](https://example.com)
- [Reference4](https://example.com)

```


---

````
The activity was detected and reported by **--------------** _(-----)_

*[ Payload Example ]*
```
blahblahblahblah  
blahblahblahblah  
blahblahblahblah  
```
````




<hr style="border-top: 3px double #bbb;">

# 📝 Incident Notification Template (Example)
```
- Please investigate whether the reported activity is legitimate or not.
- in the case the aforementioned activity is legitimate, please define the process or the business role of the user performing it as well as the business role of the corresponding host.
- In case the aforementioned activity is not deemed legitimate, please block the source IP **-----------------**  and perform a full scan of the host with the current endpoint security solution.
- Please notify us regarding the results of your investigation

```

