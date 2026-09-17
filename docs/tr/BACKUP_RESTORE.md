# Yedekleme ve geri yükleme

Kaynak: [BACKUP_RESTORE.md](../BACKUP_RESTORE.md)

Yedekler doğrulanır, veri dizini sınırları içinde açılır ve restore öncesi
 bütünlük kontrolünden geçirilir. Üretimde yedekleri collector hostundan ayrı
 saklayın; `restore --force` yalnızca doğrulanmış arşivlerde kullanılmalıdır.
