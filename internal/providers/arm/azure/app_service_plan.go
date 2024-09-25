package azure

import (
	"github.com/infracost/infracost/internal/resources/azure"
	"github.com/infracost/infracost/internal/schema"
)

func getAppServicePlanRegistryItem() *schema.RegistryItem {
	return &schema.RegistryItem{
		Name:      "Microsoft.Web/serverfarms",
		CoreRFunc: NewAppServicePlan,
	}
}
func NewAppServicePlan(d *schema.ResourceData) schema.CoreResource {
	r := &azure.AppServicePlan{
		Address:     d.Address,
		Region:      d.Region,
		SKUSize:     d.Get("sku.name").String(),
		SKUCapacity: d.Get("sku.capacity").Int(),
		Kind:        d.Get("kind").String(),
	}
	return r
}
