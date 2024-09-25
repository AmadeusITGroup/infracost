package azure

import (
	"github.com/infracost/infracost/internal/resources/azure"
	"github.com/infracost/infracost/internal/schema"
)

func getActiveDirectoryDomainServiceRegistryItem() *schema.RegistryItem {
	return &schema.RegistryItem{
		Name:      "Microsoft.AAD/domainServices",
		CoreRFunc: NewActiveDirectoryDomainService,
	}
}
func NewActiveDirectoryDomainService(d *schema.ResourceData) schema.CoreResource {
	r := &azure.ActiveDirectoryDomainService{Address: d.Address, Region: d.Region, SKU: d.Get("properties.sku").String()}
	return r
}
