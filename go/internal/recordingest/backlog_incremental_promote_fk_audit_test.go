package recordingest
import "testing"

func TestSoRFKCatalogGatesRemappedCompositeAndOptionalIdentity(t *testing.T){
 original:=[]sorPromotionFKColumn{
  {child:"source_record",childColumn:"source_batch_id",parent:"source_batch",parentColumn:"source_batch_id"},
  {child:"file_observation",childColumn:"parent_ntfs_object_id",parent:"ntfs_object",parentColumn:"ntfs_object_id"},
  {child:"usn_object_change_reason",childColumn:"source_record_id",parent:"usn_object_change",parentColumn:"source_record_id"},
  {child:"usn_object_change_reason",childColumn:"change_ordinal",parent:"usn_object_change",parentColumn:"change_ordinal"},
  {child:"usn_object_observation",childColumn:"usn_read_boundary_source_record_id",parent:"usn_read_boundary",parentColumn:"source_record_id"},
 }
 if err:=checkSoRPromotionFKColumns(original,append([]sorPromotionFKColumn(nil),original...));err!=nil{t.Fatal(err)}
 bad:=append([]sorPromotionFKColumn(nil),original...)
 bad[0].childColumn="new_undocumented_generation_fk"
 if err:=checkSoRPromotionFKColumns(bad,bad);err==nil{t.Fatal("unmapped new identity FK accepted")}
 bad=append([]sorPromotionFKColumn(nil),original...)
 bad[1].parentColumn="unmapped_new_id"
 if err:=checkSoRPromotionFKColumns(bad,bad);err==nil{t.Fatal("mapped child -> unmapped parent FK accepted")}
 private:=append([]sorPromotionFKColumn(nil),original...)
 private[0].childColumn="other_id"
 if err:=checkSoRPromotionFKColumns(original,private);err==nil{t.Fatal("private and canonical FK differences accepted")}
}
