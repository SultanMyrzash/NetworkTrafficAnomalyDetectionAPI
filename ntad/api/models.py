from django.db import models

class TrafficAnalysisResult(models.Model):
    """Model to store historical traffic analysis results"""
    timestamp = models.DateTimeField(auto_now_add=True)
    total_flows = models.IntegerField(default=0)
    benign_flows = models.IntegerField(default=0)
    attack_flows = models.IntegerField(default=0)
    attack_percentage = models.FloatField(default=0.0)
    attack_types = models.JSONField(default=dict)
    
    def __str__(self):
        return f"Analysis {self.timestamp}: {self.attack_flows} attacks"
    
    class Meta:
        ordering = ['-timestamp']