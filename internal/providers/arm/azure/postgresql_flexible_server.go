package azure

import (
	"regexp"
	"strings"

	"github.com/infracost/infracost/internal/logging"
	"github.com/infracost/infracost/internal/resources/azure"
	"github.com/infracost/infracost/internal/schema"
)

func getPostgreSQLFlexibleServerRegistryItem() *schema.RegistryItem {
	return &schema.RegistryItem{
		Name:      "Microsoft.DBforPostgreSQL/flexibleServers",
		CoreRFunc: newPostgreSQLFlexibleServer,
	}
}

func newPostgreSQLFlexibleServer(d *schema.ResourceData) schema.CoreResource {
	region := d.Region
	sku := d.Get("sku.name").String()
	storage := d.Get("properties.storage.storageSizeGB").Int() * 1024
	tier := d.Get("sku.tier").String()

	var size, version string

	splitSku := strings.Split(sku, "_")
	if len(splitSku) < 2 || len(splitSku) > 3 {
		logging.Logger.Warn().Msgf("Unrecognised PostgreSQL Flexible Server SKU format for resource %s: %s", d.Address, sku)
		return nil
	}

	if len(splitSku) > 1 {
		size = splitSku[1]
	}

	if len(splitSku) > 2 {
		version = splitSku[2]
	}

	supportedTiers := map[string]string{"Burstable": "b", "GeneralPurpose": "gp", "MemoryOptimized": "mo"}
	tier = supportedTiers[tier]

	if tier == "" {
		logging.Logger.Warn().Msgf("Unrecognised PostgreSQL Flexible Server tier prefix for resource %s: %s", d.Address, sku)
		return nil
	}

	if tier != "b" {
		coreRegex := regexp.MustCompile(`(\d+)`)
		match := coreRegex.FindStringSubmatch(size)
		if len(match) < 1 {
			logging.Logger.Warn().Msgf("Unrecognised PostgreSQL Flexible Server size for resource %s: %s", d.Address, sku)
			return nil
		}
	}

	r := &azure.PostgreSQLFlexibleServer{
		Address:         d.Address,
		Region:          region,
		SKU:             sku,
		Tier:            tier,
		InstanceType:    size,
		InstanceVersion: version,
		Storage:         storage,
	}
	return r
}
