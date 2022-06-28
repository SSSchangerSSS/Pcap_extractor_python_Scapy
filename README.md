In this project, we intend to extract the header information of the transfer layer and the network layer of the datagrams. To perform the project, npcap and scapy have been used. To receive information from .pcap files, we can use the scapy library and easily find the required information. The following is a review of the program:
To write the program, we used the scapy rdpcap section, as its name implies,Used to read the pcap file. The time section of the sleep section was also used. Sleep Used to interrupt the program. First, the number of packets and the percentage of the number of packets Is displayed for all, and after a pause (to see this information clearly) The requested information for each packet is displayed and saved to its protocol file.
To use this app:

1. Put the program file in the place of your .pcap files.

2. After running the program, enter the name of the file whose information you want to extract without an extension
--------------------------------------------------------------------------------------------------------------------------------
پروژه استخراج اطلاعات فایل pcap:

در این پروژه قصد داریم اطالعات سرآیند لابه انتقال و لایه شبکه دیتاگرام ها را استخراج کنیم.برای
انجام پروژه از npcap و scapy استفاده شده است.برای دریافت اطلاعات از فایل های pcap .می توان
از کتابخانه scapy بهره برد و به راحتی اطالعات مورد نیاز را استخراج کرد.در ادامه به بررسی
برنامه می پردازیم:
برای نوشتن برنامه از scapy بخش rdpcap را استفاده کرده ایم ، همانطور که از نام آن مشخص است
برای خواندن فایل pcap استفاده شده است.همچنین از time بخش sleep استفاده شده است.از sleep
برای ایجاد وقفه در برنامه استفاده شده است.به این صورت که ابتدا تعداد بسته ها و درصد تعداد بسته ها
نسبت به کل بسته ها نمایش داده می شود و بعد از یک وقفه)برای دیدن این اطالعات به صورت واضح(
اطلاعات خواسته شده‌ی مربوط به هریک از بسته ها نمایش و در فایل  مربوط به پروتکلش ذخیره می شود.

برای استفاده از این برنامه:

1.فایل برنامه را در محل فایل های پیکپ خود قرار دهید.

2.پس از اجرای برنامه نام فایلی که می خواهید اطلاعاتش را استخراج کنید بدون پسوند وارد کنید.
