# decode-eop-header
Little tool to decode Microsoft Exchange Online Protection header into a nice view

## Example output

```
+-------+--------------------------------+--------------------------------+
| FIELD |             VALUE              |            MEANING             |
+-------+--------------------------------+--------------------------------+
| H     | mta.example.com                | HELO/EHLO string               |
+-------+--------------------------------+--------------------------------+
| CAT   | SPOOF (Mail classified as      | Category of protection policy  |
|       | spoofing)                      |                                |
+-------+--------------------------------+--------------------------------+
| LANG  | de                             | Language of message            |
+-------+--------------------------------+--------------------------------+
| SFV   | SPM (message was marked as     | Filtering result               |
|       | spam by spam filtering)        |                                |
+-------+--------------------------------+--------------------------------+
| SCL   | 5 (marked as spam)             | Spam confidence level. A       |
|       |                                | higher value indicates the     |
|       |                                | message is more likely to be   |
|       |                                | spam.                          |
+-------+--------------------------------+--------------------------------+
| IPV   | NLI (no ip reputation data     | IP reputation status           |
|       | found)                         |                                |
+-------+--------------------------------+--------------------------------+
| PTR   | mta.example.com                | PTR of connecting IP           |
+-------+--------------------------------+--------------------------------+
| CIP   | 10.0.0.1                       | Connecting IP                  |
+-------+--------------------------------+--------------------------------+
| CTRY  | DE                             | Source country as determined   |
|       |                                | by the connecting IP address   |
+-------+--------------------------------+--------------------------------+
| BCL   |                              0 | Bulk Confidence Level. A       |
|       |                                | higher BCL indicates a bulk    |
|       |                                | mail message is more likely to |
|       |                                | generate complaints            |
+-------+--------------------------------+--------------------------------+

```